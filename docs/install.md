# 導入の手順

susanoo の GW と CLIENT を、systemd で動く Linux の機器に入れる手順。設計の考え方と各機能の詳しい説明は [policy.md](policy.md) にある。ここでの例のアドレス（LAN が 192.168.10.0/24、GW が 192.168.10.1）とインターフェースの名前は、手元の環境に合わせて読み替える。

## 必要なもの

| 機器 | 条件 |
|---|---|
| GW | Linux（x86_64 か arm64）。ルーター方式では、LAN 側と WAN 側の 2 つのネットワークのポート。nftables（`nft` コマンド）、conntrack、NFLOG が使えるカーネル。既存のルーター（プロバイダーとつなぐもの）の内側に置き、WAN 側は普通の IPv4 にする |
| CLIENT | Linux（x86_64 か arm64）と systemd。ファイルの監視には fanotify の FID 方式（Linux 5.9 以上）、自己隔離には nftables を使う。使えない機能は自動で外し、`ctl devices -json` の features に出る |
| 管理者の手元 | `susanoo ctl` を動かす機器。二段構えにするなら、ルートの認証局を置く外せる記録媒体（USB メモリなど） |

GW は通信の転送の経路に入る。導入する前に、GW を止めたときの扱い（ポリシーの `on_failure`。`fail_open` なら通信を通す）と、元の配線に戻す手順を決めておく。

## 1. 実行ファイルを用意する

ビルドする機器で（Go 1.26.8 以上と make が要る。外部とは通信しない）:

```sh
make check   # vet と試験
make dist    # bin/dist に CPU ごとの実行ファイル、SBOM、SHA256SUMS を作る
```

`bin/dist/susanoo-linux-amd64`（arm64 の機器なら `susanoo-linux-arm64`）を、GW と端末の `/usr/local/bin/susanoo` に置く。置いた後に SHA256SUMS と照らし合わせる。

```sh
sha256sum -c SHA256SUMS --ignore-missing
install -m 0755 susanoo-linux-amd64 /usr/local/bin/susanoo
susanoo version
```

`susanoo-linux-*.spdx.json` は SBOM（SPDX 2.3）で、部品（Go の標準ライブラリの版など）と実行ファイルのハッシュが書いてある。`susanoo sbom` で、置いた実行ファイルからも作れる。

## 2. GW を入れる

以下は GW の上で root で行う。

### 利用者とディレクトリ

GW は CONTROLLER と LAN 側の処理を、別々の非特権の利用者で動かす。

```sh
install -m 0644 deploy/systemd/susanoo.conf /etc/sysusers.d/susanoo.conf
systemd-sysusers
install -d -m 0755 /etc/susanoo /var/lib/susanoo
```

### 認証局と鍵

どちらか一方を選ぶ。

- 一段（手軽。認証局の鍵とポリシーの署名の鍵が GW の上にある）:

  ```sh
  susanoo ctl init -dir /etc/susanoo/controller
  ```

- 二段構え（勧める。ルートの認証局とポリシーの署名の鍵を GW の外に置く。GW を乗っ取られても、管理者の証明書と署名したポリシーは作れない）:

  ```sh
  # 管理者の手元（記録媒体）で
  susanoo ctl root init -dir /media/usb/susanoo-root
  # GW で
  susanoo ctl init -two-tier -dir /etc/susanoo/controller
  # issuer.pub を手元に持っていき、手元で
  susanoo ctl root sign-issuer -dir /media/usb/susanoo-root -pub issuer.pub -out to-gw
  # to-gw を GW に持っていき、GW で
  susanoo ctl init -issuer to-gw -dir /etc/susanoo/controller
  ```

  二段構えでは、管理者の `ctl` は `-dir /media/usb/susanoo-root` で動かす。ルートのディレクトリは、使うときだけ差す。

秘密鍵（`ca.key`、`sign.key`、`policy.key`、`issuer.key`）は外に出さない。管理者を増やすときは `ctl admin keygen` と `ctl admin issue` で管理者ごとに証明書を作る（手元の証明書をなくしたら `ctl admin revoke` で失効させる）。

### 設定とポリシー

```sh
install -m 0600 config/gw.example.json /etc/susanoo/gw.json
install -m 0600 config/policy.example.json /etc/susanoo/policy.json
```

`gw.json` を手元に合わせて直す。主な項目:

- `listen`：管理通信の待ち受け（LAN 側のアドレスとポート。例 `192.168.10.1:8443`）
- `router.lan`、`router.wan`：LAN 側と WAN 側のインターフェース。LAN 側には固定のアドレス（例 `192.168.10.1/24`）を付けておく。既存の LAN に透過で入れるときは、`router` の代わりに `bridge`（[config/gw-bridge.example.json](../config/gw-bridge.example.json)）
- `dhcp`：LAN の機器に貸すアドレスの範囲（ルーター方式だけ）
- `dns.upstreams`：上流の DNS サーバー
- `notify`：管理者への通知（Webhook、メール）。宛先のパスワードを含むので、このファイルは root だけが読めるようにする

ポリシーは、最初はグループの外部通信の制御を学習モード（`egress.default: learn`）にして始める。学習の期間（既定 14 日）が終わったら、学習した名前から許可リストの案を作り（`ctl learned suggest`）、先行適用で一部の端末から原則拒否に移る。対応の方式（`response`）も、最初は `monitor`（隔離しない）か `alert` にして、`ctl trial` で誤検知を確かめてから `enforce` にする。

### サービス

```sh
install -m 0644 deploy/systemd/susanoo-gw.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now susanoo-gw
journalctl -u susanoo-gw -f    # 起動のログを確かめる
susanoo ctl status -dir /etc/susanoo/controller -server 192.168.10.1:8443
```

`ctl status` で、ポリシー、認証局と証明書の期限、時刻の同期の状態を確かめる。GW の時刻が同期していなければ、NTP で合わせる（端末の時刻のずれは GW の時刻と比べる）。

## 3. 端末に CLIENT を入れる

### 端末の証明書

どちらか一方を選ぶ。

- 登録コード（勧める）:

  ```sh
  # 管理者の手元で（コードは 1 回だけ使える。既定の期限は 24 時間）
  susanoo ctl enroll create pc-001 -server 192.168.10.1:8443
  # 端末で（root）。鍵を作り、証明書、認証局の証明書、指示とリリースの公開鍵を受け取る
  susanoo client enroll -controller 192.168.10.1:8443 -id pc-001 -code <コード>
  ```

- 発行（登録コードを使わないとき）:

  ```sh
  # 端末で
  susanoo client keygen -dir /etc/susanoo/client
  # client.pub を GW に持っていき、GW で
  susanoo ctl issue -dir /etc/susanoo/controller -id pc-001 -pub client.pub -out pc-001
  # pc-001 の中身を端末の /etc/susanoo/client に置く（client.key はそのまま）
  ```

### 設定とサービス

```sh
install -m 0600 config/client.example.json /etc/susanoo/client.json
install -m 0644 deploy/systemd/susanoo-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now susanoo-client
```

`client.json` の `controller` を GW の `listen` に合わせる。おとり（`honeytokens`）は、利用者が触らない場所に、本物らしい名前で置く。監視する場所（`files`）は、省略すると既定の場所（認証情報、自動起動、利用者の文書など）になる。管理者の手元で `ctl devices` を実行し、端末が接続して機能（features）を申告していることを確かめる。

ユニットの `CPUQuota` と `MemoryMax` は、CLIENT の資源の確実な上限。CLIENT は設定の `resources`（既定は CPU 10%、メモリ 256 MiB）を超えると自分で監視を間引くので、ユニットの上限はそれより大きくしておく。

## 4. 運用

- 状態：`ctl status`（全体）、`ctl devices`、`ctl hosts`、`ctl events`、`ctl incident`。通知の宛先を設定していれば、隔離などをすぐに知らせる
- 誤検知：`ctl trial -since 14d` で、保存したイベントを今の検知ルールと例外で評価し直し、端末ごとに隔離していた回数と当たったルールを確かめる。平常の操作は検知ルールの例外にして配布し、もう一度 `ctl trial` で確かめてから、対応の方式を `enforce` にし、試験運用（monitor）のルールを加点にする（[policy.md](policy.md) の「試行の評価」）
- CLIENT の更新：新しい版を `make dist` で作り、`ctl upgrade sign` で署名して（二段構えならルートのディレクトリで）、`ctl upgrade push -canary <端末>` で先行適用し、問題がなければ `ctl upgrade promote` で全体に広げる。端末は版数とハッシュを確かめて入れ替え、起動し直す
- GW の更新：`ctl upgrade verify` で実行ファイルが署名した目録と合うことを確かめてから置き換え、`systemctl restart susanoo-gw`
- 証明書：端末と GW の証明書は自動で更新する。認証局の証明書（10 年）は、期限が近づいたら `ctl ca renew` で同じ鍵のまま発行し直す。二段構えの発行用の認証局（1 年）は `ctl root sign-issuer` で署名し直す
- バックアップ：`susanoo backup create -config /etc/susanoo/gw.json -out <ファイル> -passphrase-file <ファイル>`。秘密鍵を含むので、パスフレーズで暗号化し、GW の外に保管する

## 5. 止める、外す

- GW：`systemctl disable --now susanoo-gw`。`on_failure` が `fail_open` なら外部通信の制御をやめて通す（端末単位の遮断は残る）。GW を外すときは、先に端末の隔離を解除し、配線とアドレス（端末の既定の経路と DNS）を元に戻す
- CLIENT：止めても自己隔離は解除しない。外すときは、先に `ctl release <端末>` で隔離を解除してから `systemctl disable --now susanoo-client` とし、`ctl revoke <端末>` で証明書を失効させる。隔離されたまま CONTROLLER に届かない端末は、端末の上で `nft delete table inet susanoo_client` で自己隔離を消す

## 困ったとき

- 起動しない：`journalctl -u susanoo-gw`（`susanoo-client`）で理由を見る。設定の誤りは起動のときに日本語で示す
- 端末が接続しない：`client.json` の `controller`、端末の時刻、証明書の期限（`ctl devices`）、失効（`ctl devices` の状態）を確かめる
- 脆弱性を見つけたとき：[SECURITY.md](../SECURITY.md) の手順で、公開せずに知らせる
