package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"susanoo/internal/keys"
	"susanoo/internal/sign"
)

func testSigner(t *testing.T) *sign.Signer {
	t.Helper()
	priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := sign.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// version は minimal の版数と default グループの扱いを変えたポリシーを返す。
func version(t *testing.T, v int, def EgressDefault) *Policy {
	t.Helper()
	p, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	p.Version, p.IssuedAt = v, time.Date(2026, 10, 18, 0, 0, v, 0, time.UTC)
	p.Groups[0].Egress.Default = def
	return p
}

func signed(t *testing.T, s *sign.Signer, p *Policy) sign.Envelope {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(sign.PurposePolicy, data)
}

// 保存先は、署名と版数を確かめてから版を受け付け、先行適用、全体への適用、取り消しを記録する。再起動しても続く。
func TestStore(t *testing.T) {
	dir := t.TempDir()
	s := testSigner(t)
	st, err := OpenStore(dir, s.PublicKey(), version(t, 1, EgressDeny))
	if err != nil {
		t.Fatal(err)
	}
	if cur, can := st.Policies(); cur.Version != 1 || can != nil {
		t.Fatalf("最初の版 = %v、%v", cur.Version, can)
	}

	// 先行適用。グループ以外は今の版に従い、新しい版のグループは印を付けて並べる。
	if _, err := st.Apply(signed(t, s, version(t, 2, EgressLearn)), true); err != nil {
		t.Fatal(err)
	}
	eff := st.Effective()
	if eff.Version != 1 || len(eff.Groups) != 2 || eff.Groups[1].Name != "default"+CanarySuffix || eff.Groups[1].Egress.Default != EgressLearn {
		t.Errorf("先行適用中のポリシー = %+v", eff)
	}
	if got := CanaryGroupName(version(t, 2, EgressLearn), "server"); got != "default"+CanarySuffix {
		t.Errorf("新しい版にないグループの先行適用の名前 = %q", got)
	}

	// 再起動しても、今の版と先行適用の版が戻る。
	st2, err := OpenStore(dir, s.PublicKey(), version(t, 1, EgressDeny))
	if err != nil {
		t.Fatal(err)
	}
	if cur, can := st2.Policies(); cur.Version != 1 || can == nil || can.Version != 2 {
		t.Fatalf("再起動後の版 = %v、%v", cur, can)
	}
	if err := st2.Promote(); err != nil {
		t.Fatal(err)
	}
	if cur, can := st2.Policies(); cur.Version != 2 || can != nil {
		t.Errorf("全体に広げた後の版 = %v、%v", cur.Version, can)
	}
	if err := st2.Promote(); err == nil {
		t.Error("先行適用がないのに全体に広げた")
	}

	// 先行適用を取り消すと元に戻り、その版数は使えない。
	if _, err := st2.Apply(signed(t, s, version(t, 3, EgressAllow)), true); err != nil {
		t.Fatal(err)
	}
	if err := st2.Abort(); err != nil {
		t.Fatal(err)
	}
	if cur, can := st2.Policies(); cur.Version != 2 || can != nil || st2.Max() != 3 {
		t.Errorf("取り消した後の版 = %v、%v、最大 %d", cur.Version, can, st2.Max())
	}

	// 古い版、受け付けた版数以下の版、別の鍵の署名、用途の違う署名は受け付けない。
	other := testSigner(t)
	for name, env := range map[string]sign.Envelope{
		"古い版":     signed(t, s, version(t, 1, EgressAllow)),
		"取り消した版数": signed(t, s, version(t, 3, EgressAllow)),
		"別の鍵":     signed(t, other, version(t, 4, EgressAllow)),
		"用途の違う署名": s.Sign(sign.PurposeCommand, signed(t, s, version(t, 4, EgressAllow)).Payload),
	} {
		if _, err := st2.Apply(env, false); err == nil {
			t.Errorf("%s を受け付けた", name)
		}
	}

	// 全体に適用すると、先行適用は取り消される。
	st2.Apply(signed(t, s, version(t, 4, EgressLearn)), true)
	if _, err := st2.Apply(signed(t, s, version(t, 5, EgressAllow)), false); err != nil {
		t.Fatal(err)
	}
	if cur, can := st2.Policies(); cur.Version != 5 || can != nil {
		t.Errorf("全体に適用した後の版 = %v、%v", cur.Version, can)
	}
	// 保存した版は、読み直すときにも署名を確かめる。
	st3, err := OpenStore(dir, other.PublicKey(), version(t, 1, EgressDeny))
	if err == nil || !strings.Contains(err.Error(), "版 5") {
		t.Errorf("別の鍵で開いたときのエラー = %v（%v）", err, st3)
	}
}

// グループ名の「~」は先行適用の印のために使えない。
func TestGroupNameRejectsTilde(t *testing.T) {
	p := version(t, 1, EgressDeny)
	p.Groups = append(p.Groups, Group{Name: "default~canary", Egress: Egress{Default: EgressDeny}, Isolation: IsolateFull})
	if err := p.Validate(); err == nil {
		t.Error("「~」を含むグループ名を受け付けた")
	}
}
