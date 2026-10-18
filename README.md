# susanoo
Integrated Defense System

AIを使う攻撃者を想定し、「検知・遮断・隔離」を1つで提供する国産OSSの統合防御システム。開発中。

## 文書

- [機能要件](docs/requirements.md)
- [開発方針](docs/policy.md)

## ビルドと試験

Go 1.26.8 以上と make が必要。ビルドと試験は外部と通信しない。

```sh
make          # vet、試験、ビルド（bin/susanoo）
make test     # 試験だけ
make fuzz     # ファジング（FUZZTIME=30s のように時間を指定できる）
make lab-test # 検証環境の試験（root 権限が必要。sudo のパスワードを聞かれる）
```

`make lab-test` は使い捨てのネットワーク名前空間の中で動き、ホストのネットワークには触れない。

## ライセンス

[Apache License 2.0](LICENSE)
