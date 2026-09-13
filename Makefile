# tsportmap build targets. Everything here is the Go toolchain plus docker; the
# repository deliberately depends on no other tooling.

BINARY  ?= tsportmap
IMAGE   ?= tsportmap:dev

# There are no tags on a fresh clone and no git metadata at all in a source
# tarball, so both fallbacks are real cases rather than defensive noise.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/hakaitech/tsportmap/internal/obs.Version=$(VERSION)

.PHONY: all build test cover lint tidy-check docker clean

all: lint test build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/tsportmap

# -race is not optional. Every relay session is a pair of goroutines sharing a
# session table and a metrics recorder, which is precisely what the detector is
# for; a green run without it says very little.
test:
	go test -race ./...

cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { echo 'gofmt needed:'; gofmt -l .; exit 1; }

# Rewrites go.mod/go.sum in place and fails if that changed anything. tailscale.com
# is meant to be the only third-party dependency; a diff here means something
# pulled in another one or left a stale require line behind.
tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -f $(BINARY) coverage.out
