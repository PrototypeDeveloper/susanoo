# susanoo のビルドと試験。
# 外部と通信しないよう、モジュールの取得とツールチェーンの自動ダウンロードを止めている（docs/policy.md）。
# Go のモジュールは src（本体）と test（検証環境の試験）の 2 つで、それぞれのディレクトリで go コマンドを実行する。

GO      ?= go
VERSION := $(shell cat VERSION)
BIN     := $(CURDIR)/bin
LDFLAGS := -X susanoo/internal/version.Version=$(VERSION)

export GOPROXY     := off
export GOTOOLCHAIN := local

# ファジングの対象（src からのパッケージ:関数）と、1 つあたりの実行時間。
FUZZ_TARGETS := \
	./internal/sign:FuzzVerify \
	./internal/policy:FuzzParse \
	./internal/rules:FuzzParse \
	./internal/rules:FuzzEvaluate \
	./internal/behavior:FuzzDetector \
	./internal/intel:FuzzParseFeed \
	./internal/intel:FuzzParse \
	./internal/backup:FuzzExtract \
	./internal/audit:FuzzVerify \
	./internal/platform/linux:FuzzParseFanotify \
	./internal/platform/linux:FuzzParseInotify \
	./internal/platform/linux:FuzzParseFIDEvents \
	./internal/platform/linux:FuzzParseNFQueue \
	./internal/dhcp:FuzzParse \
	./internal/gw:FuzzParseARP \
	./internal/dns:FuzzParse \
	./internal/flow:FuzzParseClientHello \
	./internal/flow:FuzzParseHTTPRequest \
	./internal/flow:FuzzParseTCP \
	./internal/flow:FuzzParseNetlink \
	./internal/flow:FuzzTracker \
	./internal/privsep:FuzzParseFrame
FUZZTIME ?= 10s

.PHONY: all build test vet fmt check fuzz lab-test clean

all: check build

# 再現可能なビルドのため、パスを埋め込まず、cgo を使わない静的な実行ファイルにする。
build:
	CGO_ENABLED=0 $(GO) -C src build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/susanoo ./cmd/susanoo

test:
	$(GO) -C src test -race ./...

vet:
	$(GO) -C src vet ./...
	$(GO) -C test vet -tags lab ./...

fmt:
	gofmt -l -w src test

check: vet test
	@test -z "$$(gofmt -l src test)" || { echo "gofmt が必要なファイルがあります:"; gofmt -l src test; exit 1; }

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; fn=$${t##*:}; \
		echo "== $$pkg $$fn"; \
		$(GO) -C src test -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	done

# 検証環境の試験（root 権限が必要）。ビルドは一般ユーザーで行い、sudo は試験の実行だけに使う。
# 試験は使い捨てのネットワーク名前空間とマウント名前空間の中で動き、ホストのネットワークには触れない。
LAB_NS := sudo unshare --net --mount --propagation private
lab-test: build
	$(GO) -C src test -c -o $(BIN)/nft.test ./internal/nft
	$(GO) -C src test -c -o $(BIN)/platform-linux.test ./internal/platform/linux
	CGO_ENABLED=0 $(GO) -C src test -c -o $(BIN)/privsep.test ./internal/privsep
	$(GO) -C test test -c -tags lab -o $(BIN)/lab.test ./lab
	$(LAB_NS) $(BIN)/nft.test -test.v -test.run RealNFT
	$(LAB_NS) $(BIN)/platform-linux.test -test.v
	$(LAB_NS) $(BIN)/privsep.test -test.v -test.run 'Privileged|Harden'
	$(LAB_NS) $(BIN)/lab.test -test.v -test.timeout 5m -susanoo $(BIN)/susanoo

clean:
	rm -f $(BIN)/susanoo $(BIN)/*.test
