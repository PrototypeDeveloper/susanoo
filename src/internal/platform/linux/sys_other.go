//go:build linux && !(amd64 || arm64)

package linux

// sysNameToHandleAt は対応していないアーキテクチャでは使わない（ファイルの監視は使えない）。
const sysNameToHandleAt = ^uintptr(0)
