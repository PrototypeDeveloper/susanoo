// Package nft は nftables のルールを組み立て、nft コマンドで適用する。
//
// ルールは susanoo 専用のテーブルにまとめ、変更のたびにテーブルを丸ごと作り直す。
// 「空のテーブルを作る → 削除する → 作り直す」を 1 回の nft -f の中で行うので、変更は一度に反映され、
// 途中の状態にはならない。ほかのテーブル（ufw など）には触れない。
// ルールに埋め込むアドレスは netip の型で受け取り、その文字列表現だけを使う。
package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// DefaultPath は nft コマンドの場所。OS 付属のコマンドは絶対パスで呼ぶ。
const DefaultPath = "/usr/sbin/nft"

// テーブルの名前。
const (
	ClientTable = "susanoo_client" // CLIENT の自己隔離（C6）
	GWTable     = "susanoo_gw"     // GW の端末単位の遮断（G9）
)

// priority は susanoo のチェインの優先度。一般的なフィルター（0）より先に評価する。
const priority = "-10"

// Runner は nft のスクリプトを適用する。
type Runner interface {
	Run(ctx context.Context, script string) error
}

// Command は nft コマンドでスクリプトを適用する Runner。
type Command struct {
	Path string   // nft コマンドの絶対パス。空なら DefaultPath
	Args []string // スクリプトの前に付ける引数（試験用）
}

// Run はスクリプトを標準入力から nft -f - に渡す。
func (c Command) Run(ctx context.Context, script string) error {
	path := c.Path
	if path == "" {
		path = DefaultPath
	}
	cmd := exec.CommandContext(ctx, path, append(slices.Clone(c.Args), "-f", "-")...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// TableExists は inet のテーブル table があるかを返す。
func (c Command) TableExists(ctx context.Context, table string) (bool, error) {
	if !ifacePattern.MatchString(table) {
		return false, fmt.Errorf("nft: テーブルの名前 %q が不正です", table)
	}
	path := c.Path
	if path == "" {
		path = DefaultPath
	}
	cmd := exec.CommandContext(ctx, path, append(slices.Clone(c.Args), "list", "table", "inet", table)...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = []string{}
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && strings.Contains(stderr.String(), "No such file or directory") {
		return false, nil
	}
	return false, fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
}

// Element は集合の要素（アドレスと、有効期限までの残り時間。期限がなければ 0）。
type Element struct {
	Addr    netip.Addr
	Expires time.Duration
}

// ListSet は inet のテーブル table の集合 set の要素を返す（nft -j list set）。
func (c Command) ListSet(ctx context.Context, table, set string) ([]Element, error) {
	if !ifacePattern.MatchString(table) || !ifacePattern.MatchString(set) {
		return nil, fmt.Errorf("nft: テーブル %q か集合 %q の名前が不正です", table, set)
	}
	path := c.Path
	if path == "" {
		path = DefaultPath
	}
	cmd := exec.CommandContext(ctx, path, append(slices.Clone(c.Args), "-j", "list", "set", "inet", table, set)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseSetJSON(stdout.Bytes())
}

// parseSetJSON は nft -j list set の出力から要素を取り出す。要素は「アドレス」か、
// 期限つきなら {"elem": {"val": アドレス, "expires": 秒}} の形で並ぶ。アドレスでない要素（範囲など）は飛ばす。
func parseSetJSON(data []byte) ([]Element, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nft: 集合の出力を解析できません: %w", err)
	}
	var out []Element
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var plain string
			if json.Unmarshal(raw, &plain) == nil {
				if a, err := netip.ParseAddr(plain); err == nil {
					out = append(out, Element{Addr: a})
				}
				continue
			}
			var timed struct {
				Elem struct {
					Val     json.RawMessage `json:"val"`
					Expires int64           `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &timed) != nil || json.Unmarshal(timed.Elem.Val, &plain) != nil {
				continue
			}
			if a, err := netip.ParseAddr(plain); err == nil {
				out = append(out, Element{Addr: a, Expires: time.Duration(timed.Elem.Expires) * time.Second})
			}
		}
	}
	return out, nil
}

// replaceTable はテーブルを作り直すスクリプトの先頭部分を返す。
func replaceTable(name string) string {
	return fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", name, name)
}

// DeleteTable はテーブルを削除するスクリプトを返す。テーブルがなくても失敗しない。
func DeleteTable(name string) string { return replaceTable(name) }
