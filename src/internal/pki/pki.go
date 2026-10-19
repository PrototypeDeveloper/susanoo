// Package pki は内部の認証局（CA）と、相互TLSで使う証明書の発行を扱う（M1）。
//
// 鍵はすべて ed25519。証明書には役割と ID を表す URI（susanoo://<役割>/<ID>）を入れ、
// 接続相手の識別にはこの URI を使う。サーバーになる役割（controller、gw）の証明書には、
// 役割ごとに決まった名前（controller.susanoo.internal など）も入れ、接続先の確認に使う。
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"susanoo/internal/fsutil"
	"susanoo/internal/keys"
)

// Role は証明書の持ち主の役割。
type Role string

const (
	RoleController Role = "controller" // CONTROLLER
	RoleGW         Role = "gw"         // GW
	RoleClient     Role = "client"     // CLIENT（端末）
	RoleAdmin      Role = "admin"      // 管理者（CLI）
)

func (r Role) valid() bool {
	switch r {
	case RoleController, RoleGW, RoleClient, RoleAdmin:
		return true
	}
	return false
}

// isServer はサーバーとして接続を受ける役割かどうかを返す。
func (r Role) isServer() bool { return r == RoleController || r == RoleGW }

const (
	// CAValidity は認証局の証明書の有効期間。
	CAValidity = 10 * 365 * 24 * time.Hour
	// LeafValidity は端末やサーバーの証明書の有効期間。定期的に更新する前提で短くする。
	LeafValidity = 90 * 24 * time.Hour
	// clockSkew は機器間の時刻のずれを見込んで、有効期間の開始を早める幅。
	clockSkew = 5 * time.Minute

	uriScheme = "susanoo"
	// serverNameSuffix はサーバー証明書の名前の接尾辞。.internal は私的な用途のために予約された名前。
	serverNameSuffix = ".susanoo.internal"

	// IssuerValidity は、ルートの認証局が署名する発行用の認証局（二段構え）の有効期間。期限の前に、ルートの鍵で署名し直す。
	IssuerValidity = 365 * 24 * time.Hour

	// CACertFile と CAKeyFile は、認証局のディレクトリに置くファイルの名前。二段構えでは、CACertFile はルートの認証局の証明書で、
	// CAKeyFile（ルートの秘密鍵）は GW に置かない。
	CACertFile = "ca.crt"
	CAKeyFile  = "ca.key"
	// IssuerCertFile、IssuerKeyFile、IssuerPubFile は、二段構えで GW に置く発行用の認証局のファイルの名前。
	IssuerCertFile = "issuer.crt"
	IssuerKeyFile  = "issuer.key"
	IssuerPubFile  = "issuer.pub"
)

// IssuerRoles は、発行用の認証局が発行できる役割。管理者（admin）の証明書は、ルートの認証局だけが発行する
// （GW を乗っ取られても、管理者の証明書は作れない）。名前の制約（name constraints）で、証明書の検証のときに強制する。
var IssuerRoles = []Role{RoleClient, RoleController, RoleGW}

// ServerName は役割 r のサーバー証明書に入れる名前を返す。接続する側はこの名前で相手を確かめる。
func ServerName(r Role) string { return string(r) + serverNameSuffix }

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Identity は証明書の持ち主（役割と ID）。
type Identity struct {
	Role Role
	ID   string
}

// Validate は役割と ID が正しい形か確かめる。ID は英小文字、数字、「.」「_」「-」で 63 文字まで。
func (id Identity) Validate() error {
	if !id.Role.valid() {
		return fmt.Errorf("pki: 不明な役割です: %q", id.Role)
	}
	if !idPattern.MatchString(id.ID) {
		return fmt.Errorf("pki: ID の形が正しくありません: %q", id.ID)
	}
	return nil
}

// URI は証明書に入れる URI を返す。
func (id Identity) URI() *url.URL {
	return &url.URL{Scheme: uriScheme, Host: string(id.Role), Path: "/" + id.ID}
}

func (id Identity) String() string { return id.URI().String() }

// IdentityFromCert は証明書から持ち主を取り出す。susanoo の URI がちょうど 1 つ入っている必要がある。
func IdentityFromCert(cert *x509.Certificate) (Identity, error) {
	var found []*url.URL
	for _, u := range cert.URIs {
		if u.Scheme == uriScheme {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return Identity{}, fmt.Errorf("pki: 証明書に %s の URI が %d 個あります（1 個が必要）", uriScheme, len(found))
	}
	u := found[0]
	id := Identity{Role: Role(u.Host), ID: strings.TrimPrefix(u.Path, "/")}
	if err := id.Validate(); err != nil {
		return Identity{}, err
	}
	if u.String() != id.String() {
		return Identity{}, fmt.Errorf("pki: URI の形が正しくありません: %q", u)
	}
	return id, nil
}

// CA は内部の認証局。
type CA struct {
	Cert  *x509.Certificate   // 証明書に署名する認証局の証明書（二段構えなら発行用の認証局）
	Root  *x509.Certificate   // 信頼の起点（ルートの認証局。一段なら Cert と同じ）
	Chain []*x509.Certificate // 発行した証明書に連ねる認証局の証明書（二段構えなら発行用の認証局。一段なら空）
	key   ed25519.PrivateKey
}

// NewCA は新しい認証局を作る。name は証明書に入れる名前。
func NewCA(name string, now time.Time) (*CA, error) {
	return newSelfSigned(name, now, 0)
}

// NewRootCA は二段構えのルートの認証局を作る。発行用の認証局（1 段）に署名できる。秘密鍵は GW に置かない。
func NewRootCA(name string, now time.Time) (*CA, error) {
	return newSelfSigned(name, now, 1)
}

func newSelfSigned(name string, now time.Time, pathLen int) (*CA, error) {
	priv, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"susanoo"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("pki: 認証局の証明書を作れません: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, key: priv, Root: cert}, nil
}

// LoadCA はディレクトリ dir から認証局を読む。
//
// 二段構えのディレクトリ（発行用の認証局の秘密鍵 IssuerKeyFile がある）では、発行用の認証局を返す。発行した証明書には、
// 発行用の認証局の証明書を連ねる（Chain）。信頼の起点（Root）はルートの認証局の証明書（CACertFile）。
func LoadCA(dir string) (*CA, error) {
	if _, err := os.Stat(filepath.Join(dir, IssuerKeyFile)); err == nil {
		return loadIssuer(dir)
	}
	cert, err := ReadCertFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, err
	}
	priv, err := keys.LoadPrivate(filepath.Join(dir, CAKeyFile))
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("pki: 認証局の証明書ではありません")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(priv.Public()) {
		return nil, errors.New("pki: 認証局の証明書と秘密鍵が対応していません")
	}
	return &CA{Cert: cert, key: priv, Root: cert}, nil
}

// loadIssuer は二段構えの発行用の認証局を読み、ルートの認証局が署名したものかを確かめる。
func loadIssuer(dir string) (*CA, error) {
	root, err := ReadCertFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, fmt.Errorf("pki: ルートの認証局の証明書を読めません: %w", err)
	}
	issuer, err := ReadCertFile(filepath.Join(dir, IssuerCertFile))
	if err != nil {
		return nil, fmt.Errorf("pki: 発行用の認証局の証明書がありません（ルートの鍵で署名して置いてください）: %w", err)
	}
	priv, err := keys.LoadPrivate(filepath.Join(dir, IssuerKeyFile))
	if err != nil {
		return nil, err
	}
	if err := CheckIssuer(root, issuer, priv.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return &CA{Cert: issuer, key: priv, Root: root, Chain: []*x509.Certificate{issuer}}, nil
}

// CheckIssuer は、issuer がルートの認証局 root の署名した発行用の認証局で、公開鍵が pub であることを確かめる。
func CheckIssuer(root, issuer *x509.Certificate, pub ed25519.PublicKey) error {
	if !issuer.IsCA || issuer.CheckSignatureFrom(root) != nil {
		return errors.New("pki: 発行用の認証局の証明書が、ルートの認証局の署名したものではありません")
	}
	if p, ok := issuer.PublicKey.(ed25519.PublicKey); !ok || !p.Equal(pub) {
		return errors.New("pki: 発行用の認証局の証明書と秘密鍵が対応していません")
	}
	return nil
}

// SignIssuer は、ルートの認証局で、公開鍵 pub の発行用の認証局の証明書に署名する。発行用の認証局は、名前の制約で
// IssuerRoles の役割の証明書と、サーバーの名前（*.susanoo.internal）だけを発行でき、さらに下の認証局は作れない。
func (ca *CA) SignIssuer(pub ed25519.PublicKey, name string, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if ca.Root != ca.Cert || ca.Cert.MaxPathLenZero || ca.Cert.MaxPathLen < 1 {
		return nil, errors.New("pki: 発行用の認証局には、二段構えのルートの認証局（ctl root init で作ったもの）だけが署名できます")
	}
	if validity <= 0 || validity > IssuerValidity {
		return nil, fmt.Errorf("pki: 有効期間 %s は 0 より長く %s までにしてください", validity, IssuerValidity)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, r := range IssuerRoles {
		roles = append(roles, string(r))
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: name, Organization: []string{"susanoo"}},
		NotBefore:                   now.Add(-clockSkew),
		NotAfter:                    earlier(now.Add(validity), ca.Cert.NotAfter),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedURIDomains:         roles,
		PermittedDNSDomains:         []string{strings.TrimPrefix(serverNameSuffix, ".")},
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: 発行用の認証局の証明書を作れません: %w", err)
	}
	return x509.ParseCertificate(der)
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// ChainOf は、この認証局が発行した証明書 leaf に、発行用の認証局の証明書を連ねたもの（TLS で示す順）を返す。
func (ca *CA) ChainOf(leaf *x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate{leaf}, ca.Chain...)
}

// ExpiresAt は、この認証局で発行できる期限（発行用の認証局なら、その証明書の期限）を返す。
func (ca *CA) ExpiresAt() time.Time { return ca.Cert.NotAfter }

// Save は認証局の証明書と秘密鍵をディレクトリ dir に保存する。秘密鍵は所有者だけが読める。
func (ca *CA) Save(dir string) error {
	if err := keys.SavePrivate(filepath.Join(dir, CAKeyFile), ca.key); err != nil {
		return err
	}
	return WriteCertFile(filepath.Join(dir, CACertFile), ca.Cert)
}

// Pool は認証局の証明書だけを含む証明書の集合を返す。相互TLSの検証に使う。
func (ca *CA) Pool() *x509.CertPool {
	if ca.Root != nil {
		p := x509.NewCertPool()
		p.AddCert(ca.Root)
		return p
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// Issue は公開鍵 pub の持ち主 id に、有効期間 LeafValidity の証明書を発行する。秘密鍵は持ち主の機器から出さない前提で、
// 公開鍵だけを受け取る。
func (ca *CA) Issue(pub ed25519.PublicKey, id Identity, now time.Time) (*x509.Certificate, error) {
	return ca.IssueFor(pub, id, now, LeafValidity)
}

// IssueFor は Issue と同じだが、有効期間を validity（LeafValidity まで）にする。
func (ca *CA) IssueFor(pub ed25519.PublicKey, id Identity, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if !ca.CanIssue(id.Role) {
		return nil, fmt.Errorf("pki: 発行用の認証局は役割 %s の証明書を発行できません（ルートの認証局で発行してください）", id.Role)
	}
	return ca.issue(pub, id, now, validity)
}

// TwoTier は、この認証局がルートの認証局の署名した発行用の認証局かどうかを返す。
func (ca *CA) TwoTier() bool { return !ca.Root.Equal(ca.Cert) }

// CanIssue は、この認証局が役割 role の証明書を発行できるかを返す。発行用の認証局は名前の制約の内側（IssuerRoles）に限る。
func (ca *CA) CanIssue(role Role) bool {
	return !ca.TwoTier() || slices.Contains(IssuerRoles, role)
}

// issue は役割を確かめずに証明書を発行する（IssueFor の本体。試験では、発行用の認証局の鍵を盗んだ者の偽造に使う）。
func (ca *CA) issue(pub ed25519.PublicKey, id Identity, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if validity <= 0 || validity > LeafValidity {
		return nil, fmt.Errorf("pki: 有効期間 %s は 0 より長く %s までにしてください", validity, LeafValidity)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pki: 公開鍵の長さが %d バイトです（%d バイトが必要）", len(pub), ed25519.PublicKeySize)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.ID, OrganizationalUnit: []string{string(id.Role)}, Organization: []string{"susanoo"}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{id.URI()},
	}
	if id.Role.isServer() {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		tmpl.DNSNames = []string{ServerName(id.Role)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: 証明書を発行できません: %w", err)
	}
	return x509.ParseCertificate(der)
}

// NewLeaf は鍵の生成と証明書の発行をまとめて行い、TLS で使える形で返す。
// 認証局と同じ機器で動くもの（GWに同居するCONTROLLERなど）と試験のために使う。
func (ca *CA) NewLeaf(id Identity, now time.Time) (tls.Certificate, error) {
	priv, err := keys.Generate()
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := ca.Issue(priv.Public().(ed25519.PublicKey), id, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	return TLSChain(ca.ChainOf(cert), priv), nil
}

// IssuedAt は証明書を発行した時刻を返す（有効期間の開始は、時刻のずれを見込んで発行より早めてある）。
// 失効（その時刻より前に発行した証明書を無効にする）の判断に使う。
func IssuedAt(cert *x509.Certificate) time.Time { return cert.NotBefore.Add(clockSkew) }

// RenewalDue は、証明書の有効期間の残りが 3 分の 1 を切ったかを返す（M1）。この時期から同じ鍵で更新する。
func RenewalDue(cert *x509.Certificate, now time.Time) bool {
	total := cert.NotAfter.Sub(IssuedAt(cert))
	return cert.NotAfter.Sub(now) < total/3
}

// TLSCertificate は証明書と秘密鍵を crypto/tls で使う形にする。
func TLSCertificate(cert *x509.Certificate, priv ed25519.PrivateKey) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv, Leaf: cert}
}

// TLSChain は、証明書の連なり（先頭が自分の証明書）と秘密鍵から tls.Certificate を作る。
func TLSChain(chain []*x509.Certificate, priv ed25519.PrivateKey) tls.Certificate {
	c := tls.Certificate{PrivateKey: priv, Leaf: chain[0]}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c
}

// WriteChainFile は証明書の連なり（先頭が自分の証明書）を PEM でファイルに書く。
func WriteChainFile(path string, chain ...*x509.Certificate) error {
	var data []byte
	for _, c := range chain {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return fsutil.WriteFileAtomic(path, data, 0o644)
}

// ReadChainFile は PEM のファイルの証明書をすべて読む（先頭が自分の証明書）。
func ReadChainFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pki: %s は PEM 形式の証明書ではありません", path)
	}
	return out, nil
}

// WriteCertFile は証明書を PEM 形式で保存する。
func WriteCertFile(path string, cert *x509.Certificate) error {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return fsutil.WriteFileAtomic(path, data, 0o644)
}

// ReadCertFile は PEM 形式の証明書を読む。
func ReadCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pki: %s は PEM 形式の証明書ではありません", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// newSerial は 128 ビットの乱数でシリアル番号を作る。
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
