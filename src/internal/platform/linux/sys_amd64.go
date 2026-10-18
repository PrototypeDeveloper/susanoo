//go:build linux && amd64

package linux

// sysNameToHandleAt は name_to_handle_at(2) のシステムコールの番号（標準ライブラリにないため）。
const sysNameToHandleAt = 303
