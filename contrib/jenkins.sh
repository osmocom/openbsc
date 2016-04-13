#!/usr/bin/env bash

set -ex

rm -rf deps/install
mkdir deps || true
export LD_LIBRARY_PATH=$PWD/deps/install/lib
cd deps
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE $PARALLEL_MAKE install


cd ../
osmo-deps.sh libosmo-abis
cd libosmo-abis
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../install/lib/pkgconfig ./configure --prefix=$PWD/../install  
PKG_CONFIG_PATH=$PWD/..//install/lib/pkgconfig $MAKE $PARALLEL_MAKE install

cd ../
osmo-deps.sh libosmo-netif
cd libosmo-netif
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../install/lib/pkgconfig ./configure --prefix=$PWD/../install  
PKG_CONFIG_PATH=$PWD/..//install/lib/pkgconfig $MAKE $PARALLEL_MAKE install

cd ../
osmo-deps.sh libosmo-sccp
cd libosmo-sccp
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../install/lib/pkgconfig ./configure --prefix=$PWD/../install  
PKG_CONFIG_PATH=$PWD/..//install/lib/pkgconfig $MAKE $PARALLEL_MAKE install

cd ../
osmo-deps.sh libsmpp34
cd libsmpp34
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE install

cd ../
osmo-deps.sh openggsn
cd openggsn
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../install/lib/pkgconfig ./configure --prefix=$PWD/../install  
PKG_CONFIG_PATH=$PWD/..//install/lib/pkgconfig $MAKE $PARALLEL_MAKE install

cd ../../openbsc
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../deps/install/lib/pkgconfig ./configure --enable-osmo-bsc --enable-nat $SMPP $MGCP --enable-vty-tests --enable-external-tests
PKG_CONFIG_PATH=$PWD/../deps/install/lib/pkgconfig $MAKE $PARALLEL_MAKE
PKG_CONFIG_PATH=$PWD/../deps/install/lib/pkgconfig LD_LIBRARY_PATH=$PWD/../deps/install/lib $MAKE check
PKG_CONFIG_PATH=$PWD/../deps/install/lib/pkgconfig LD_LIBRARY_PATH=$PWD/../deps/install/lib $MAKE distcheck
