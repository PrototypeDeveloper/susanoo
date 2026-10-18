package honeytoken

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"strings"
)

// Kind はおとりの種類。
type Kind string

const (
	KindAWS  Kind = "aws"  // AWS の認証情報（~/.aws/credentials など）
	KindSSH  Kind = "ssh"  // SSH の秘密鍵（~/.ssh/id_ed25519 など）
	KindEnv  Kind = "env"  // AI サービスの API キーなどを書いた .env
	KindText Kind = "text" // パスワードの一覧を装った文書
)

// Generate は種類 k のおとりの中身を作る。毎回ちがう値になる。
func Generate(k Kind) ([]byte, error) {
	r := newRand()
	switch k {
	case KindAWS:
		return fmt.Appendf(nil, "[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\nregion = ap-northeast-1\n",
			randString(r, upperDigits, 16), randString(r, base64Chars, 40)), nil
	case KindSSH:
		return sshPrivateKey(r)
	case KindEnv:
		return fmt.Appendf(nil, "ANTHROPIC_API_KEY=sk-ant-api03-%sAA\nOPENAI_API_KEY=sk-proj-%s\nDATABASE_URL=postgres://app:%s@db.internal:5432/production\n",
			randString(r, urlChars, 93), randString(r, urlChars, 156), randString(r, alnum, 24)), nil
	case KindText:
		return fmt.Appendf(nil, "社内システム アカウント一覧（取扱注意）\n\n経理システム\tID: keiri-admin\tPW: %s\nVPN\tID: vpn-user01\tPW: %s\nNAS\tID: admin\tPW: %s\n",
			randString(r, alnum, 14), randString(r, alnum, 14), randString(r, alnum, 14)), nil
	}
	return nil, fmt.Errorf("honeytoken: 不明な種類です: %q", k)
}

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	base64Chars = alnum + "+/"
	urlChars    = alnum + "-_"
)

func newRand() *mrand.Rand {
	var seed [32]byte
	rand.Read(seed[:])
	return mrand.New(mrand.NewChaCha8(seed))
}

func randString(r *mrand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

// sshPrivateKey は OpenSSH 形式（openssh-key-v1、暗号化なし）の ed25519 の秘密鍵を作る。
// 本物の鍵として読めるが、どこにも登録されていないので使えない。
func sshPrivateKey(r *mrand.Rand) ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	var pubBlob bytes.Buffer
	writeSSHString(&pubBlob, []byte("ssh-ed25519"))
	writeSSHString(&pubBlob, pub)

	var private bytes.Buffer
	check := r.Uint32()
	binary.Write(&private, binary.BigEndian, check)
	binary.Write(&private, binary.BigEndian, check)
	writeSSHString(&private, []byte("ssh-ed25519"))
	writeSSHString(&private, pub)
	writeSSHString(&private, priv)
	writeSSHString(&private, []byte("deploy@server"))
	for i := byte(1); private.Len()%8 != 0; i++ {
		private.WriteByte(i)
	}

	var key bytes.Buffer
	key.WriteString("openssh-key-v1\x00")
	writeSSHString(&key, []byte("none")) // 暗号の方式
	writeSSHString(&key, []byte("none")) // 鍵の導出の方式
	writeSSHString(&key, nil)            // 鍵の導出の引数
	binary.Write(&key, binary.BigEndian, uint32(1))
	writeSSHString(&key, pubBlob.Bytes())
	writeSSHString(&key, private.Bytes())

	enc := base64.StdEncoding.EncodeToString(key.Bytes())
	var out strings.Builder
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(out.String()), nil
}

func writeSSHString(b *bytes.Buffer, s []byte) {
	binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.Write(s)
}
