#!/bin/sh

GOPHISH_ROOT="/opt/gophish"

rm -rf "${GOPHISH_ROOT}" >/dev/null 2>&1

git clone https://github.com/gophish/gophish "${GOPHISH_ROOT}"
cd "${GOPHISH_ROOT}"

# Additional OPSEC patches may be applied here
# git patch /tmp/opsec.patch

wget -q -c "https://golang.org/dl/go1.17.7.linux-amd64.tar.gz"
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.7.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin
go get -v && go build -v
