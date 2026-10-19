# 脆弱性の報告

susanoo は、ネットワークの関所（GW）と端末の監視（CLIENT）を担う防御のためのソフトウェアです。脆弱性は利用者の環境を直接危険にさらすため、見つけた方は、公開する前に開発者に知らせてください。

## 報告の方法

- **公開の Issue やプルリクエストには書かないでください。**
- このリポジトリの GitHub の「Security」タブの「Report a vulnerability」（非公開の脆弱性の報告）から送ってください。報告者と開発者だけが見られます。
- 日本の「情報セキュリティ早期警戒パートナーシップ」に沿って、IPA（独立行政法人情報処理推進機構）に届け出ることもできます。その場合は、JPCERT/CC が開発者との調整を行います。開発者は、この枠組みでの調整に応じます。

報告には、分かる範囲で次のことを書いてください。

- 版数（`susanoo version`）と、使っているモード（GW、CLIENT、ctl）
- 再現の手順（設定の例、送ったパケットやコマンド）と、起きたこと
- 考えられる影響（例：隔離の解除、署名の検証の回避、権限の分離の破り、検知の回避、停止）
- 環境（Linux の版、CPU、接続形態）

## 対応の目安

| 段階 | 目安 |
|---|---|
| 受け取ったことの連絡 | 5 営業日以内 |
| 影響の評価と、修正の方針の連絡 | 30 日以内 |
| 修正した版の公開 | 原則として報告から 90 日以内 |

修正した版を公開するまでは、内容を公表しないようお願いします。公表の時期は、報告者（と JPCERT/CC）と相談して決めます。修正した版の公開と同時に、影響、対象の版、回避策をリリースの説明に書き、報告者の希望に応じて謝辞を載せます。

## 対象

| 対象とするもの | 対象としないもの |
|---|---|
| susanoo の実行ファイル（GW、CLIENT、CONTROLLER、ctl）の脆弱性 | 設定の誤りによるもの（例：管理通信のポートをインターネットに公開した） |
| 署名と証明書の検証、鍵の扱い、管理通信の相互TLS | 端末の root の権限を奪われた後の振る舞い（設計の前提。GW の生存監視と遮断で補う） |
| 権限の分離（執行部と非特権のプロセス）を越える攻撃 | [docs/policy.md](docs/policy.md) の制限の表に書いた既知の制限 |
| 検知、遮断、隔離を外から無効にする方法 | 第三者のサービスや、susanoo が使う外部のプログラム（nft など）そのものの脆弱性 |
| LAN やインターネットから届くデータ（DNS、DHCP、ARP、TLS など）の解析の不具合 | |

確かめるときは、自分の管理する環境（使い捨ての仮想マシンやネットワーク名前空間など）だけで行い、他人のネットワークや機器に影響を与えないでください。

## 対象の版

開発中（0.x）の間は、最新の版だけを修正します。

---

## Reporting a vulnerability (English)

Please do not open a public issue. Report vulnerabilities privately through GitHub's "Report a vulnerability" button in the Security tab of this repository. Reports through IPA / JPCERT/CC (the Information Security Early Warning Partnership in Japan) are also welcome. We aim to acknowledge reports within 5 business days, share an assessment within 30 days, and release a fix within 90 days. Please keep the details confidential until a fixed version is released. Only the latest 0.x version receives fixes.
