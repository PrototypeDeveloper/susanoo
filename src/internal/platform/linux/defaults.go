//go:build linux

package linux

import "path/filepath"

// DefaultWatchPaths は既定で監視する重要な場所（認証情報、権限、自動起動、シェルの起動設定）を返す。
// 存在しない場所は監視しない。
func DefaultWatchPaths() []string {
	paths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
		"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/systemd/system", "/etc/ld.so.preload", "/etc/profile.d", "/etc/ssh/sshd_config",
		"/root/.ssh", "/root/.bashrc", "/root/.profile",
	}
	homes, _ := filepath.Glob("/home/*")
	for _, h := range homes {
		for _, p := range []string{".ssh", ".bashrc", ".profile", ".config/autostart", ".config/systemd/user"} {
			paths = append(paths, filepath.Join(h, p))
		}
	}
	return paths
}

// DefaultProtectPaths は既定で大量の変更を監視する場所（利用者の文書など）を返す。
// 日本語の環境の名前（ドキュメントなど）も含める。
func DefaultProtectPaths() []string {
	var paths []string
	homes, _ := filepath.Glob("/home/*")
	for _, h := range homes {
		for _, d := range []string{"Documents", "Desktop", "Pictures", "ドキュメント", "デスクトップ", "ピクチャ"} {
			paths = append(paths, filepath.Join(h, d))
		}
	}
	return paths
}
