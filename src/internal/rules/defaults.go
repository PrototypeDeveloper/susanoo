package rules

import (
	"time"

	"susanoo/internal/config"
	"susanoo/internal/event"
)

// 既定のルール。配布したルールに同じ ID があれば置き換え、なければ既定のまま残る（Merge）。
//
//   - フェーズ1の検知（おとりへの接触など）は加点（enforce）で、どれも 100 点（既定のしきい値で 1 回で隔離する）
//   - 振る舞いの検知（2b-1）、脅威情報（2b-2）、CLIENT の検知（2c-1）の検知結果と、CLIENT のイベントの条件のルール（2c-2）は、
//     誤検知が出やすいため試験運用（monitor）。ctl rules stats で回数を確かめ、平常の操作を例外で除いてから加点にする
//
// 条件のルールは、構造で判断するもの（親子関係、実行ファイルの場所、回数、AI エージェントと操作の組み合わせ）だけを既定にする。
// コマンドラインの文字列の型で判断するルールは環境に合わせて書くものなので、配布するルール（config/rules.example.json）の例にする。
// 命令の名前は、実行ファイルの実体の名前（process.file.name。fanotify のイベントから取るので、すぐ終わるプロセスでも分かる）と、
// 起動したときの名前（process.name、comm）のどちらかが一覧にあれば当てはまる。シンボリックリンクで起動した命令は 2 つが違う
// （sh が dash、df が gnudf など）。

// Defaults は既定のルール。名前は隔離の理由として台帳に載る。
var Defaults = []Rule{
	{ID: "honeytoken", Name: "おとりへの接触", Finding: event.FindingTypeHoneytoken, Mode: ModeEnforce, Score: 100},
	{ID: "mass-change", Name: "短時間の大量変更", Finding: event.FindingTypeMassChange, Mode: ModeEnforce, Score: 100},
	{ID: "gateway-spoofing", Name: "ゲートウェイのなりすまし", Finding: event.FindingTypeGatewaySpoofing, Mode: ModeEnforce, Score: 100},
	{ID: "ip-spoofing", Name: "アドレスのなりすまし", Finding: event.FindingTypeIPSpoofing, Mode: ModeEnforce, Score: 100},
	{ID: "heartbeat-lost", Name: "ハートビートの途絶", Finding: event.FindingTypeHeartbeatLost, Mode: ModeEnforce, Score: 100},
	{ID: "tamper", Name: "防御の仕組みの改ざん", Finding: event.FindingTypeTamper, Mode: ModeEnforce, Score: 0}, // 記録して警告する
	// 振る舞いの検知（G6）は誤検知が出やすいため、試験運用から始める。
	{ID: "beacon", Name: "周期的な通信", Finding: event.FindingTypeBeacon, Mode: ModeMonitor, Score: 40},
	{ID: "large-upload", Name: "大量の送信", Finding: event.FindingTypeLargeUpload, Mode: ModeMonitor, Score: 50},
	{ID: "internal-scan", Name: "LAN 内のスキャン", Finding: event.FindingTypeInternalScan, Mode: ModeMonitor, Score: 60},
	{ID: "new-destinations", Name: "新しい宛先の急増", Finding: event.FindingTypeNewDestinations, Mode: ModeMonitor, Score: 30},
	{ID: "off-hours", Name: "時間外の通信", Finding: event.FindingTypeOffHours, Mode: ModeMonitor, Score: 20},
	// 脅威情報（G7）。遮断の一覧は GW が止めるので、危険度による隔離は、一覧の質を確かめてから有効にする。
	{ID: "threat-intel", Name: "脅威情報に当てはまる通信", Finding: event.FindingTypeThreatIntel, Mode: ModeMonitor, Score: 50},
	// CLIENT の検知（2c-1）。管理者の作業やパッケージの更新でも当てはまるため、試験運用から始め、例外で平常の操作を除く。
	{ID: "persistence", Name: "永続化の場所の変更", Finding: event.FindingTypePersistence, Mode: ModeMonitor, Score: 40},
	{ID: "privilege-change", Name: "権限の設定の変更", Finding: event.FindingTypePrivilegeChange, Mode: ModeMonitor, Score: 40},
	{ID: "privilege-escalation", Name: "権限昇格", Finding: event.FindingTypePrivilegeEscalation, Mode: ModeMonitor, Score: 20},
	{ID: "credential-access", Name: "認証情報へのアクセス", Finding: event.FindingTypeCredentialAccess, Mode: ModeMonitor, Score: 50},
	{ID: "kernel-module", Name: "カーネルモジュールの読み込み", Finding: event.FindingTypeKernelModule, Mode: ModeMonitor, Score: 30},
	// プロセス単位の通信の制御（C7）で拒否した（試験運用なら拒否に当たった）接続。ポリシーで決めた通りの拒否なので点は小さい。
	{ID: "app-control", Name: "アプリの通信の拒否", Finding: event.FindingTypeAppControl, Mode: ModeMonitor, Score: 10},

	// 不審な親子関係（C8。T2 脆弱性の悪用、T1 細工した文書やページ）。CLIENT のプロセスの起動のイベントの条件で検知する。
	{ID: "shell-from-service", Name: "サービスのプロセスからのシェルの起動", Class: "process", Mode: ModeMonitor, Score: 60, Severity: event.SeverityHigh,
		Description: "Web サーバーやデータベースなどのサービスのプロセスがシェルを起動した（脆弱性の悪用で命令を実行された疑い）",
		Match:       all(fileNameIn(shells...), parentIn(serviceProcesses...))},
	{ID: "shell-from-app", Name: "アプリケーションからのシェルの起動", Class: "process", Mode: ModeMonitor, Score: 50, Severity: event.SeverityHigh,
		Description: "ブラウザー、文書の閲覧、チャットなどのアプリケーションがシェルを起動した（細工した文書やページから命令を実行された疑い）",
		Match:       all(fileNameIn(shells...), parentIn(desktopApps...))},
	// 正規ツールの不審な使い方（C8、T4）と、侵入した後の偵察（T3）。
	{ID: "exec-from-temp", Name: "一時的な場所からの実行", Class: "process", Mode: ModeMonitor, Score: 30,
		Description: "一時的なディレクトリ（/tmp、/var/tmp、/dev/shm）に置いた実行ファイルを起動した（持ち込んだプログラムの実行の疑い）",
		Match:       anyOf(prefix("process.file.path", "/tmp/"), prefix("process.file.path", "/var/tmp/"), prefix("process.file.path", "/dev/shm/"))},
	{ID: "enumeration", Name: "連続する列挙", Class: "process", Mode: ModeMonitor, Score: 40,
		Description: "利用者、ホスト、ネットワーク、プロセスなどの情報を調べる命令を、短い間に何度も実行した（侵入した後の偵察の疑い）",
		Threshold:   &Threshold{Count: 10, Window: config.Duration(2 * time.Minute)},
		Match:       all(fileNameIn(enumerationCommands...))},
	{ID: "internal-connections-burst", Name: "LAN の中への多数の接続", Class: "network", Mode: ModeMonitor, Score: 30,
		Description: "端末のプロセスが、短い間に LAN の中の多くの相手に接続した（横展開の探索の疑い。GW では見えない LAN の中の通信を CLIENT の記録で見る）",
		Threshold:   &Threshold{Count: 30, Window: config.Duration(time.Minute)},
		Match: all(Cond{Field: "connection_info.direction_id", Op: "eq", Value: float64(2)},
			*anyOf(cidr("dst_endpoint.ip", "10.0.0.0/8"), cidr("dst_endpoint.ip", "172.16.0.0/12"), cidr("dst_endpoint.ip", "192.168.0.0/16")))},
	// ログオン（C4、2h）。管理者が遠隔で作業する環境では当てはまるため、試験運用から始める。
	{ID: "logon-failures", Name: "ログオンの失敗の連続", Class: "logon", Mode: ModeMonitor, Score: 40,
		Description: "端末へのログオンの失敗が、短い間に続いた（パスワードの総当たりや、盗んだ認証情報の試しの疑い）",
		Threshold:   &Threshold{Count: 10, Window: config.Duration(5 * time.Minute)},
		Match:       all(Cond{Field: "status_id", Op: "eq", Value: float64(event.StatusFailure)})},
	{ID: "remote-root-logon", Name: "root での遠隔ログオン", Class: "logon", Mode: ModeMonitor, Score: 30,
		Description: "root で遠隔からログオンした（root の遠隔ログオンを禁じていない端末で、管理者の作業でなければ乗っ取りの疑い）",
		Match: all(Cond{Field: "activity_id", Op: "eq", Value: float64(event.AuthLogon)}, Cond{Field: "status_id", Op: "eq", Value: float64(event.StatusSuccess)},
			Cond{Field: "is_remote", Op: "eq", Value: "true"}, Cond{Field: "user.name", Op: "eq", Value: "root"})},
	// AI エージェントの監視（C9、T10）。CLIENT が付けた帰属（unmapped.agent）と操作の組み合わせで検知する。
	{ID: "agent-privilege", Name: "AI エージェントによる権限の操作", Class: "process", Mode: ModeMonitor, Score: 40, Severity: event.SeverityHigh,
		Description: "AI エージェントの配下のプロセスが、sudo などで権限を得ようとした（プロンプトインジェクションで操られた疑い）",
		Match:       all(exists("unmapped.agent.name"), fileNameIn("sudo", "su", "pkexec", "doas"))},
	{ID: "agent-sensitive-action", Name: "AI エージェントによる要注意の操作", Class: "finding", Mode: ModeMonitor, Score: 50, Severity: event.SeverityHigh,
		Description: "AI エージェントの配下のプロセスが、永続化や権限の設定の変更、権限昇格、認証情報の読み取り、おとりへの接触、大量の変更、許可していない宛先への接続をした",
		Match: all(exists("unmapped.agent.name"), in("finding_info.types", event.FindingTypePersistence, event.FindingTypePrivilegeChange,
			event.FindingTypePrivilegeEscalation, event.FindingTypeCredentialAccess, event.FindingTypeHoneytoken, event.FindingTypeMassChange,
			event.FindingTypeAppControl))},
}

// 条件のルールで使う名前。
var (
	shells = []string{"sh", "bash", "dash", "zsh", "fish", "ksh"}
	// サービスのプロセス（Web サーバー、アプリケーションサーバー、データベース、ファイルとメールのサーバー、DNS）。
	serviceProcesses = []string{"nginx", "apache2", "httpd", "php-fpm", "postgres", "postmaster", "mysqld", "mariadbd", "redis-server", "mongod",
		"memcached", "smbd", "vsftpd", "dovecot", "exim4", "named", "unbound"}
	// 利用者が文書やページを開くアプリケーション（ブラウザー、オフィス、PDF、メール、チャット）。
	desktopApps = []string{"firefox", "chrome", "chromium", "brave", "msedge", "soffice.bin", "evince", "okular", "thunderbird", "evolution",
		"slack", "discord", "zoom", "teams"}
	// 端末の情報を調べる命令（利用者、ホスト、ネットワーク、プロセス、装置、環境）。
	enumerationCommands = []string{"whoami", "id", "uname", "hostname", "hostnamectl", "ifconfig", "ip", "netstat", "ss", "arp", "route",
		"ps", "w", "who", "last", "lastlog", "lsblk", "lsmod", "lspci", "lsusb", "lscpu", "nproc", "df", "mount", "env", "printenv", "getent",
		"lsof", "crontab", "dmidecode"}
)

func all(c ...Cond) *Cond   { return &Cond{All: c} }
func anyOf(c ...Cond) *Cond { return &Cond{Any: c} }
func in(field string, values ...string) Cond {
	return Cond{Field: field, Op: "in", Values: values}
}

// fileNameIn は、実行ファイルの実体の名前か、起動したときの名前が names のどれかという条件。
func fileNameIn(names ...string) Cond {
	return Cond{Any: []Cond{in("process.file.name", names...), in("process.name", names...)}}
}
func parentIn(names ...string) Cond { return in("process.parent_process.name", names...) }
func exists(field string) Cond      { return Cond{Field: field, Op: "exists"} }
func prefix(field, v string) Cond   { return Cond{Field: field, Op: "prefix", Value: v} }
func cidr(field, v string) Cond     { return Cond{Field: field, Op: "cidr", Value: v} }
