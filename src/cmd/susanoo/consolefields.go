package main

// Web コンソール（2p）の入力欄。よく使う項目だけを入力欄にし、残り（通知、おとり、監視する場所の細かい指定など）は
// JSON の欄で編集する。入力欄を空にすると、その項目を設定ファイルから消す（既定値を使う）。

// consoleField は入力欄の 1 つ。Path は設定の JSON の中の場所（「.」で区切る）。
type consoleField struct {
	Section     string          `json:"section"`
	Path        string          `json:"path"`
	Label       string          `json:"label"`
	Type        string          `json:"type"` // text、number、duration、bool、list（文字の並び）、numbers（数の並び）、objlist（Key の値の並び）
	Key         string          `json:"key,omitempty"`
	Help        string          `json:"help,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	Options     []consoleOption `json:"options,omitempty"`
}

type consoleOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

func consoleFields(kind string) []consoleField {
	if kind == "client" {
		return clientConsoleFields
	}
	return gwConsoleFields
}

var gwConsoleFields = []consoleField{
	{Section: "基本", Path: "listen", Label: "管理通信の待ち受け", Type: "text", Placeholder: "192.168.10.1:8443", Help: "LAN 側のアドレスとポート。CLIENT と ctl はここに接続する"},
	{Section: "基本", Path: "pki_dir", Label: "鍵と証明書のディレクトリ", Type: "text", Placeholder: "/etc/susanoo/controller"},
	{Section: "基本", Path: "state_dir", Label: "状態のディレクトリ", Type: "text", Placeholder: "/var/lib/susanoo/gw", Help: "台帳、監査ログ、イベントを置く"},
	{Section: "基本", Path: "policy", Label: "ポリシーのファイル", Type: "text", Placeholder: "/etc/susanoo/policy.json", Help: "最初の版だけに使う。その後は ctl policy push で配布する"},
	{Section: "基本", Path: "heartbeat_timeout", Label: "ハートビートの途絶の時間", Type: "duration", Placeholder: "30s", Help: "これより長くハートビートがなければ隔離する"},
	{Section: "基本", Path: "max_clock_skew", Label: "端末の時刻のずれの上限", Type: "duration", Placeholder: "2m"},

	{Section: "ルーター方式", Path: "router.lan", Label: "LAN 側のインターフェース", Type: "text", Placeholder: "enp2s0", Help: "ブリッジ方式のときは空にする"},
	{Section: "ルーター方式", Path: "router.wan", Label: "WAN 側のインターフェース", Type: "text", Placeholder: "enp1s0"},
	{Section: "ルーター方式", Path: "router.wan_dhcp", Label: "WAN 側のアドレスを DHCP で得る", Type: "bool"},
	{Section: "ルーター方式", Path: "router.admin_ports", Label: "LAN から受け付ける管理用のポート", Type: "numbers", Placeholder: "22", Help: "「,」で区切る。空なら既定（22）"},
	{Section: "ルーター方式", Path: "router.ipv6", Label: "LAN の IPv6 を転送する", Type: "bool", Help: "LAN 側のインターフェースに /64 の IPv6 アドレスが要る"},
	{Section: "ルーター方式", Path: "router.trusted_routers", Label: "LAN のルーターとして認める機器", Type: "list", Placeholder: "02:00:00:00:00:01", Help: "MAC アドレスを「,」で区切る"},

	{Section: "ブリッジ方式", Path: "bridge.name", Label: "ブリッジ", Type: "text", Placeholder: "br0", Help: "ルーター方式のときは空にする"},
	{Section: "ブリッジ方式", Path: "bridge.lan", Label: "LAN 側のポート", Type: "text"},
	{Section: "ブリッジ方式", Path: "bridge.wan", Label: "上流のルーター側のポート", Type: "text"},
	{Section: "ブリッジ方式", Path: "bridge.gateway", Label: "上流のルーターのアドレス", Type: "text", Help: "空ならブリッジの既定の経路から"},

	{Section: "DHCP（ルーター方式）", Path: "dhcp.range", Label: "貸し出すアドレスの範囲", Type: "text", Placeholder: "192.168.10.100-192.168.10.199"},
	{Section: "DHCP（ルーター方式）", Path: "dhcp.lease_time", Label: "貸し出しの期間", Type: "duration", Placeholder: "1h"},
	{Section: "DHCP（ルーター方式）", Path: "dhcp.dns", Label: "端末に知らせる DNS サーバー", Type: "list", Help: "空なら GW のリゾルバ"},

	{Section: "DNS", Path: "dns.upstreams", Label: "上流の DNS サーバー", Type: "objlist", Key: "address", Placeholder: "192.168.0.1:53", Help: "アドレスとポートを「,」で区切る。DNS over TLS の名前は JSON の欄で tls_name に書く"},
	{Section: "DNS", Path: "dns.log_queries", Label: "問い合わせを記録する", Type: "bool"},

	{Section: "動作", Path: "enforce", Label: "GW で遮断する", Type: "bool", Help: "いいえなら隔離の判断だけをして、GW では遮断しない"},
	{Section: "動作", Path: "flow_log", Label: "通信を記録する", Type: "bool"},
	{Section: "動作", Path: "privilege_separation", Label: "権限を分ける", Type: "bool"},
	{Section: "動作", Path: "controller_user", Label: "CONTROLLER の利用者", Type: "text", Placeholder: "susanoo-ctl"},
	{Section: "動作", Path: "lan_user", Label: "LAN 側の処理の利用者", Type: "text", Placeholder: "susanoo-net"},
}

var clientConsoleFields = []consoleField{
	{Section: "基本", Path: "controller", Label: "CONTROLLER", Type: "text", Placeholder: "192.168.10.1:8443", Help: "GW の管理通信の待ち受けのアドレスとポート"},
	{Section: "基本", Path: "pki_dir", Label: "鍵と証明書のディレクトリ", Type: "text", Placeholder: "/etc/susanoo/client"},
	{Section: "基本", Path: "state_dir", Label: "状態のディレクトリ", Type: "text", Placeholder: "/var/lib/susanoo/client"},
	{Section: "基本", Path: "heartbeat_interval", Label: "ハートビートの間隔", Type: "duration", Placeholder: "5s"},

	{Section: "監視", Path: "process_monitor", Label: "プロセスを監視する", Type: "bool"},
	{Section: "監視", Path: "connection_monitor", Label: "通信とプロセスを結び付ける", Type: "bool"},
	{Section: "監視", Path: "kernel_modules", Label: "カーネルモジュールの読み込みを検知する", Type: "bool"},
	{Section: "監視", Path: "logons.enabled", Label: "ログオンを記録する", Type: "bool"},
	{Section: "監視", Path: "files.protect", Label: "大量の変更を監視する場所", Type: "list", Help: "「,」で区切る。空なら既定（利用者の文書など）"},
	{Section: "監視", Path: "files.mass_files", Label: "大量の変更とみなすファイルの数", Type: "number", Placeholder: "200"},
	{Section: "監視", Path: "files.mass_window", Label: "大量の変更を数える時間", Type: "duration", Placeholder: "30s"},
	{Section: "監視", Path: "files.wide", Label: "守る場所の外の大量の変更を監視するファイルシステム", Type: "list", Help: "空なら既定（/、/home、/srv）"},
	{Section: "監視", Path: "files.wide_files", Label: "守る場所の外で大量の変更とみなすファイルの数", Type: "number", Placeholder: "1000"},

	{Section: "制御", Path: "isolation", Label: "自己隔離する", Type: "bool"},
	{Section: "制御", Path: "app_control", Label: "プロセス単位の通信の制御を使う", Type: "bool"},

	{Section: "資源", Path: "resources.cpu_percent", Label: "CPU の使用率の上限（%）", Type: "number", Placeholder: "10", Help: "1 つの CPU を使い切ると 100。超えたら監視を間引く"},
	{Section: "資源", Path: "resources.memory_mb", Label: "メモリの上限（MiB）", Type: "number", Placeholder: "256"},

	{Section: "権限", Path: "privilege_separation", Label: "権限を分ける", Type: "bool"},
	{Section: "権限", Path: "analyzer_user", Label: "解析部の利用者", Type: "text", Placeholder: "nobody"},
	{Section: "権限", Path: "evidence.logs", Label: "証拠として集めるログ", Type: "list", Help: "絶対パスを「,」で区切る。空なら既定の場所"},
}
