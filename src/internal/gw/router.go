package gw

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"susanoo/internal/nft"
)

// ipForwardPath は IPv4 の転送を有効にする sysctl のファイル。
const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// Router はルーター方式（G1）のルールを適用し、IPv4 の転送を有効にする。
type Router struct {
	Rules nft.Router
	NFT   nft.Runner

	forwardPath  string // 試験で置き換える
	acceptRAPath string
}

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
	path = r.acceptRAPath
	if path == "" {
		path = fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", r.Rules.LAN) // 名前は Script で確かめてある
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("gw: LAN のルーター広告を受け付けない設定にできません: %w", err)
	}
	return nil
}
