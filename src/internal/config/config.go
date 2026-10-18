// Package config は各モードの設定ファイル（JSON）を読むための共通の処理をまとめる。
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Load は path の JSON を v に読む。知らない項目は書き間違いとみなして拒否する。
func Load(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("config: %s を解析できません: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("config: %s の JSON の後に余分なデータがあります", path)
	}
	return nil
}

// Resolve は設定ファイルに書かれた相対パスを、設定ファイルのあるディレクトリからのパスにする。
// 空のパスと絶対パスはそのまま返す。
func Resolve(configPath, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(configPath), p)
}

// Duration は "5s" や "1m30s" の形で書く時間。
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New(`時間は "5s" のような文字列で書いてください`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("時間 %q を解析できません", s)
	}
	if v < 0 {
		return fmt.Errorf("時間 %q が負です", s)
	}
	*d = Duration(v)
	return nil
}

// Or は d が 0 なら def を返す。
func (d Duration) Or(def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return time.Duration(d)
}
