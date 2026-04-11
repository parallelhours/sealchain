# Building sealchain

## Prerequisites

Go 1.21 or later. The module declares `go 1.26.1` — the Go toolchain will manage this automatically via `GOTOOLCHAIN=auto` (the default since Go 1.21).

## Run Tests

```bash
go test ./...
```

With the race detector (recommended before submitting changes):

```bash
go test -race ./...
```

Expected output:

```
ok      github.com/parallelhours/sealchain                0.XXs
ok      github.com/parallelhours/sealchain/cmd/sealcheck  0.XXs
```

## Build sealcheck

Local development build:

```bash
go build -o sealcheck ./cmd/sealcheck
./sealcheck verify audit.log
```

Install globally (replaces any existing version):

```bash
go install github.com/parallelhours/sealchain/cmd/sealcheck@latest
```

## Use sealchain as a Library

Add the dependency:

```bash
go get github.com/parallelhours/sealchain@latest
```

Import it:

```go
import sealchain "github.com/parallelhours/sealchain"
```

See [docs/integration.md](docs/integration.md) for a full integration guide.

## Note: Module Path History

This module was previously published at `github.com/pmonday/sealchain` (pre-v0.2.0). If you have that path in your `go.mod`, update it to `github.com/parallelhours/sealchain` and run:

```bash
go mod tidy
```
