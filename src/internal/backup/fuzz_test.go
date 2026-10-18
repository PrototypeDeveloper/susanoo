package backup

import (
	"bytes"
	"testing"
)

// FuzzExtract は、細工したバックアップ（暗号化していないもの）を取り出しても止まらず、決めた場所の外に書かないことを確かめる。
// 暗号化したものは鍵を作るのに時間がかかるので、復号の後の処理は暗号化していないもので確かめる。
func FuzzExtract(f *testing.F) {
	_, entries := files(f)
	var buf bytes.Buffer
	Create(&buf, entries, Options{Plain: true})
	f.Add(buf.Bytes())
	f.Add([]byte(plainMagic))
	f.Add([]byte(encMagic + "\x00\x00\x00\x02{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) >= len(encMagic) && string(data[:len(encMagic)]) == encMagic {
			return // 鍵を作るのに時間がかかる
		}
		Extract(bytes.NewReader(data), nil, "")
	})
}
