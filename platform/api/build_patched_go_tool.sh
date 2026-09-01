#!/bin/sh
set -eu

name="$1"
repository="$2"
commit="$3"
package="$4"

git init "/src/${name}"
git -C "/src/${name}" remote add origin "https://github.com/${repository}.git"
git -C "/src/${name}" fetch --depth 1 origin "${commit}"
git -C "/src/${name}" checkout --detach FETCH_HEAD
cd "/src/${name}"

go get \
  golang.org/x/crypto@v0.55.0 \
  golang.org/x/mod@v0.40.0 \
  golang.org/x/net@v0.58.0 \
  golang.org/x/text@v0.41.0
go mod tidy
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "/out/${name}" "${package}"
