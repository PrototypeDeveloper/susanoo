package policy

import "slices"

// 段階的な適用（M2）。新しい版を、指定した端末にだけ先に適用する（先行適用）。
//
// 先行適用の間は、今の版のグループに、新しい版のグループを名前に CanarySuffix を付けて並べたポリシー（WithCanary）を
// GW で使う。先行適用の端末は、新しい版のグループ（CanaryGroupName）に入れる。対応の方式や障害時の動作など、
// グループ以外の項目は今の版に従う。全体に広げる（promote）と新しい版が今の版になり、取り消す（abort）と元に戻る。

// CanarySuffix は先行適用のグループの名前に付ける印。ポリシーのグループ名には「~」を使えないので、名前はぶつからない。
const CanarySuffix = "~canary"

// WithCanary は、今の版 current に、先行適用の版 canary のグループを並べたポリシーを返す。canary が nil なら current を返す。
func WithCanary(current, canary *Policy) *Policy {
	if canary == nil {
		return current
	}
	p := *current
	p.Groups = slices.Clone(current.Groups)
	for _, g := range canary.Groups {
		g.Name += CanarySuffix
		p.Groups = append(p.Groups, g)
	}
	return &p
}

// CanaryGroupName は、グループ group の端末を先行適用するときに入れるグループの名前を返す。
// 先行適用の版にそのグループがなければ、その版の既定のグループに入れる。
func CanaryGroupName(canary *Policy, group string) string {
	if group == "" || !canary.HasGroup(group) {
		group = DefaultGroup
	}
	return group + CanarySuffix
}
