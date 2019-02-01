#!/bin/bash

VERSION=`date -u +%Y%m%d`
LDFLAGS="-X main.VERSION=$VERSION -s -w"
GCFLAGS=""

OSES=(linux windows)
ARCHS=(amd64 386)
for os in ${OSES[@]}; do
        for arch in ${ARCHS[@]}; do
                suffix=""
                if [ "$os" == "windows" ]
                then
                        suffix=".exe"
                fi
                env CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o p2pclient_${os}_${arch}${suffix} github.com/hikaricai/p2p_tun/p2pclient
                env CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o p2pserver_${os}_${arch}${suffix} github.com/hikaricai/p2p_tun/p2pserver
                tar -zcf p2ptun-${os}-${arch}-$VERSION.tar.gz p2pclient_${os}_${arch}${suffix} p2pserver_${os}_${arch}${suffix}
        done
done

# ARM
ARMS=(7)
for v in ${ARMS[@]}; do
        env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o p2pclient_linux_arm$v  github.com/hikaricai/p2p_tun/p2pclient
        env CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=$v go build -ldflags "$LDFLAGS" -gcflags "$GCFLAGS" -o p2pserver_linux_arm$v  github.com/hikaricai/p2p_tun/p2pserver
done
tar -zcf p2ptun-linux-arm-$VERSION.tar.gz p2pclient_linux_arm* p2pserver_linux_arm*
