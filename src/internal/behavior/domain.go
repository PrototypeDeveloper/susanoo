package behavior

import "strings"

// secondLevel は、国別のドメインで、組織の名前の上に付く分類の名前（co.jp、com.au など）。
// 公開されている一覧（Public Suffix List）は使わず、よく使われるものだけで近似する。
var secondLevel = map[string]bool{
	"co": true, "ne": true, "or": true, "ac": true, "go": true, "ed": true, "gr": true, "lg": true, "ad": true,
	"com": true, "net": true, "org": true, "gov": true, "edu": true, "mil": true,
}

// BaseDomain は名前を、登録できる単位（example.com、example.co.jp など）にまとめる。
// 名前として扱えないもの（アドレス、1 つのラベルだけの名前など）は空を返す。
func BaseDomain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(name) > 253 || strings.ContainsAny(name, " /:\\") {
		return ""
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	if n < 2 || hasEmpty(labels) {
		return ""
	}
	if isNumeric(labels[n-1]) {
		return "" // アドレス
	}
	if n >= 3 && len(labels[n-1]) == 2 && secondLevel[labels[n-2]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

func hasEmpty(labels []string) bool {
	for _, l := range labels {
		if l == "" {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
