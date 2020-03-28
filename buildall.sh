#!/bin/bash

# First make sure the docker image exists
docker build --tag adityapk00/zcash:latest docker

mkdir -p artifacts/mac
mkdir -p artifacts/linux
mkdir -p artifacts/win

# Build for Mac
if [[ "$OSTYPE" == "darwin"* ]]; then
    make clean
    CONFIGURE_FLAGS="--disable-tests --disable-mining --disable-bench" ./zcutil/build.sh -j$(nproc)
    strip src/zcashd
    cp src/zcashd artifacts/mac
fi

# Build for linux in docker
docker run --rm -v $(pwd):/opt/zcash adityapk00/zcash:latest bash -c "cd /opt/zcash-linux && git pull && CONFIGURE_FLAGS=\"--disable-tests --disable-mining --disable-bench\" ./zcutil/build.sh -j$(nproc) && strip src/zcashd && cp src/zcashd /opt/zcash/artifacts/linux/"

# Build for win in docker
docker run --rm -v $(pwd):/opt/zcash adityapk00/zcash:latest bash -c "cd /opt/zcash-win && git pull && CONFIGURE_FLAGS=\"--disable-tests --disable-mining --disable-bench\" HOST=x86_64-w64-mingw32 ./zcutil/build.sh -j$(nproc) && strip src/zcashd.exe && cp src/zcashd.exe /opt/zcash/artifacts/win/"
