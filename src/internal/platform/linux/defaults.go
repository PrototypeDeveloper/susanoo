//go:build linux

package linux

import (
	"os"
	"path/filepath"
)

// 既定で監視する場所。存在しない場所は監視しない。利用者のホームは起動時に /home/* を調べる。

// homes は利用者のホーム（/root を含む）を返す。
func homes() []string {
	hs, _ := filepath.Glob("/home/*")
	return append(hs, "/root")
}

// DefaultWatchPaths は既定で変更を記録するだけの場所（名前の解決、信頼する認証局、パッケージの入手元など）を返す。
func DefaultWatchPaths() []string {
	return []string{
		"/etc/hosts", "/etc/nsswitch.conf", "/etc/fstab",
		"/etc/ssl/certs", "/etc/ca-certificates.conf", "/usr/local/share/ca-certificates",
		"/etc/apt/sources.list", "/etc/apt/sources.list.d", "/etc/apt/trusted.gpg.d",
	}
}

// DefaultPersistencePaths は既定で変更を検知結果にする、永続化に使われる場所（自動起動、cron、サービス、シェルの起動設定、
// 共有ライブラリの先読み、カーネルモジュールの自動読み込みなど）を返す（C4）。
func DefaultPersistencePaths() []string {
	paths := []string{
		"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs",
		"/etc/systemd/system", "/etc/systemd/system/*.wants", "/etc/systemd/user", "/etc/init.d", "/etc/rc.local", "/etc/xdg/autostart",
		"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/environment", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
		"/etc/modules-load.d", "/etc/modprobe.d", "/etc/udev/rules.d", "/etc/update-motd.d", "/etc/apt/apt.conf.d", "/etc/NetworkManager/dispatcher.d",
	}
	for _, h := range homes() {
		for _, p := range []string{".ssh/authorized_keys", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv", ".config/autostart", ".config/systemd/user"} {
			paths = append(paths, filepath.Join(h, p))
		}
	}
	return paths
}

// DefaultPrivilegePaths は既定で変更を検知結果にする、権限の設定の場所（利用者、sudo、PAM、polkit、SSH サーバーの設定）を返す（C4）。
func DefaultPrivilegePaths() []string {
	return []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
		"/etc/pam.d", "/etc/security", "/etc/polkit-1/rules.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	}
}

// DefaultSensitive は既定で読み取りを検知結果にする認証情報のファイルと、それをふだん読むプログラムを返す（C8、C9）。
// ブラウザーの保存した認証情報や、AI エージェントなどのサービスの鍵の置き場所は環境によって違うため、設定で足す。
func DefaultSensitive() []SensitiveSpec {
	auth := []string{"su", "sudo", "login", "sshd", "sshd-session", "passwd", "chpasswd", "chage", "unix_chkpwd", "cron", "CRON", "atd",
		"gdm-session-worker", "lightdm", "sddm-helper", "polkit-agent-helper-1", "systemd-logind"}
	specs := []SensitiveSpec{
		{Path: "/etc/shadow", Readers: auth},
		{Path: "/etc/gshadow", Readers: auth},
	}
	for _, h := range homes() {
		specs = append(specs,
			SensitiveSpec{Path: filepath.Join(h, ".ssh", "id_*"), Exclude: []string{"*.pub"}, Readers: []string{"ssh", "ssh-add", "ssh-agent", "ssh-keygen", "scp", "sftp"}},
			SensitiveSpec{Path: filepath.Join(h, ".aws", "credentials"), Readers: []string{"aws"}},
			SensitiveSpec{Path: filepath.Join(h, ".netrc"), Readers: []string{"curl", "wget", "git", "git-remote-https", "ftp"}},
			SensitiveSpec{Path: filepath.Join(h, ".docker", "config.json"), Readers: []string{"docker", "dockerd", "docker-compose"}},
			SensitiveSpec{Path: filepath.Join(h, ".kube", "config"), Readers: []string{"kubectl", "helm"}},
			SensitiveSpec{Path: filepath.Join(h, ".config", "gh", "hosts.yml"), Readers: []string{"gh"}},
		)
	}
	return specs
}

// DefaultWidePaths は既定で守る場所の外の大量の変更を監視するファイルシステム（その上の場所）を返す。
// 同じファイルシステムの場所は 1 つにまとめて監視する。
func DefaultWidePaths() []string {
	var paths []string
	for _, p := range []string{"/", "/home", "/srv"} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			paths = append(paths, p)
		}
	}
	return paths
}

// DefaultProtectPaths は既定で大量の変更を監視する場所（利用者の文書など）を返す。
// 日本語の環境の名前（ドキュメントなど）も含める。
func DefaultProtectPaths() []string {
	var paths []string
	hs, _ := filepath.Glob("/home/*")
	for _, h := range hs {
		for _, d := range []string{"Documents", "Desktop", "Pictures", "ドキュメント", "デスクトップ", "ピクチャ"} {
			paths = append(paths, filepath.Join(h, d))
		}
	}
	return paths
}
