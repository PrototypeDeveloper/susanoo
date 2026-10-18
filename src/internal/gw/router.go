package gw

import (
	"context"
	"fmt"
	"os"

	"susanoo/internal/nft"
)

// ipForwardPath は IPv4 の転送を有効にする sysctl のファイル。
const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// Router はルーター方式（G1）のルールを適用し、IPv4 の転送を有効にする。
type Router struct {
	Rules nft.Router
	NFT   nft.Runner

	forwardPath string // 試験で置き換える
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
	return nil
}
