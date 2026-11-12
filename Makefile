BIN = dkim-milter

all: $(BIN)

# Created only when missing, so local edits are never overwritten.
config.go:
	awk 'NR <= 2 && (/^\/\/go:build ignore$$/ || /^$$/) { next } { print }' config.def.go > $@

$(BIN): config.go *.go go.mod go.sum
	go build -o $@ .

test: config.go
	go vet ./...
	go test ./...

clean:
	rm -f $(BIN)

.PHONY: all test clean
