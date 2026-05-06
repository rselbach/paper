set dotenv-load

addr := env_var_or_default("PAPER_ADDR", ":8081")
db := env_var_or_default("PAPER_DB", "/tmp/paper-dev.db")
bin := "bin/paper"

default:
    just --list

run:
    PAPER_ADDR={{addr}} PAPER_DB={{db}} go run .

build:
    mkdir -p bin
    go build -o {{bin}} .

serve: build
    PAPER_ADDR={{addr}} PAPER_DB={{db}} ./{{bin}}

test:
    go test ./...

vet:
    go vet ./...

check:
    go test ./...
    go vet ./...

race:
    go test -race ./...

clean:
    rm -rf bin
