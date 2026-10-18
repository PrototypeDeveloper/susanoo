package intel

import (
	"bufio"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// hosts の形式のファイルで、遮断の意味を持たない名前。
var hostsNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Feed は一覧のファイルから取り出したドメインとアドレスの範囲。
type Feed struct {
	Domains []string // 正規化して重複を除き、並べたもの
	CIDRs   []string // 重なりを除き、並べたもの
	Skipped int      // 解釈できずに飛ばした行
}

// maxLine は 1 行の上限。
const maxLine = 64 << 10

// ParseFeed は一覧のファイルを読む。1 行に 1 つの項目を書いた、よく使われる形式を受け付ける。
//
//   - ドメイン（evil.example）、アドレス（203.0.113.5）、アドレスの範囲（203.0.113.0/24）
//   - hosts の形式（0.0.0.0 evil.example。1 行に複数の名前も可）
//   - URL（http://evil.example/login。ホストの部分を使う）
//   - 広告の遮断の形式（||evil.example^）
//
// 「#」と「!」で始まる行と、行の「#」より後ろは注釈として読み飛ばす。
func ParseFeed(r io.Reader) (Feed, error) {
	var f Feed
	domains := map[string]bool{}
	var prefixes []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxLine)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		fields := strings.Fields(line)
		items := fields[:1]
		if len(fields) > 1 {
			// hosts の形式：先頭のアドレスは名前の向け先なので、2 つ目からを使う。
			if a, err := netip.ParseAddr(fields[0]); err == nil && (a.IsUnspecified() || a.IsLoopback()) {
				items = fields[1:]
			} else {
				f.Skipped++
				continue
			}
		}
		ok := false
		for _, item := range items {
			if hostsNames[strings.ToLower(item)] {
				ok = true
				continue
			}
			d, p := parseItem(item)
			switch {
			case d != "":
				domains[d] = true
				ok = true
			case p.IsValid():
				prefixes = append(prefixes, p)
				ok = true
			}
		}
		if !ok {
			f.Skipped++
		}
	}
	if err := sc.Err(); err != nil {
		return f, err
	}
	for d := range domains {
		f.Domains = append(f.Domains, d)
	}
	slices.Sort(f.Domains)
	for _, p := range MergePrefixes(prefixes) {
		f.CIDRs = append(f.CIDRs, p.String())
	}
	return f, nil
}

// parseItem は 1 つの項目を、ドメインかアドレスの範囲にする。
func parseItem(s string) (string, netip.Prefix) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "||") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "||"), "^")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", netip.Prefix{}
		}
		s = u.Hostname()
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "*."), ".")
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Zone() != "" || p.Bits() == 0 {
			return "", netip.Prefix{}
		}
		return "", p.Masked()
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		a = a.Unmap()
		if a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() {
			return "", netip.Prefix{}
		}
		return "", netip.PrefixFrom(a, a.BitLen())
	}
	return NormalizeDomain(s), netip.Prefix{}
}
