run:
  go run ./cmd/bitscrunch/bitscrunch.go

build:
  go build -ldflags "-s -w" ./cmd/bitscrunch/bitscrunch.go
