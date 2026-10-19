package gw

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"susanoo/internal/nft"
)

// ipForwardPath は IPv4 の転送を有効にする sysctl のファイル。
const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// Router はルーター方式（G1）のルールを適用し、IPv4 の転送（Rules.IPv6 なら IPv6 の転送も）を有効にする。
type Router struct {
	Rules nft.Router
	NFT   nft.Runner

	forwardPath  string // 試験で置き換える
	acceptRAPath string
	sysctlDir    string // /proc/sys/net/ipv6/conf（試験で置き換える）
}

const ipv6ConfDir = "/proc/sys/net/ipv6/conf"

// Apply はルールを適用し、IPv4 の転送を有効にする。
func (r *Router) Apply(ctx context.Context) error {
	script, err := r.Rules.Script()
	if err != nil {
		return err
	}
	if err := r.NFT.Run(ctx, script); err != nil {
		return err
	}
	path := r.forwardPath
	if path == "" {
		path = ipForwardPath
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("gw: IPv4 の転送を有効にできません: %w", err)
	}
	// GW が LAN のルーターなので、LAN の機器のルーター広告には従わない（不正な RA で GW 自身の経路を変えられないため）。
	// IPv6 を使えない環境では、このファイルがない。
	dir := r.sysctlDir
	if dir == "" {
		dir = ipv6ConfDir
	}
	path = r.acceptRAPath
	if path == "" {
		path = filepath.Join(dir, r.Rules.LAN, "accept_ra") // 名前は Script で確かめてある
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("gw: LAN のルーター広告を受け付けない設定にできません: %w", err)
	}
	if !r.Rules.IPv6 {
		return nil
	}
	// IPv6 を転送する。転送を有効にすると accept_ra が 1 の装置は RA に従わなくなるので、WAN 側（上流のルーターの RA で
	// アドレスと既定の経路を得ることがある）は先に 2 にする。
	for _, w := range []struct{ file, value, what string }{
		{filepath.Join(dir, r.Rules.WAN, "accept_ra"), "2", "WAN のルーター広告を受け付ける設定"},
		{filepath.Join(dir, "all", "forwarding"), "1", "IPv6 の転送"},
	} {
		if err := os.WriteFile(w.file, []byte(w.value+"\n"), 0o644); err != nil {
			return fmt.Errorf("gw: %sにできません: %w", w.what, err)
		}
	}
	return nil
}
