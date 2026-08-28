#!/bin/sh
# Builds a static mbedtls for the released binaries.
#
#   sh tools/build_mbedtls.sh <install-prefix>
#
# The distributions' packages are used for ordinary development; this exists so
# every released binary carries the same TLS, whatever it was cross compiled
# from. 3.6 is the LTS branch, and the one ESP-IDF ships, so the bytes the
# protocol code produces here are the bytes it produces on an ESP32.
#
# CC, CXX and CMAKE_EXTRA select the target when cross compiling.
#
# Fatal warnings are off because mbedtls builds itself with -Werror=format,
# and mingw's printf takes MSVCRT's view of %lld. That is mbedtls' own
# development setting, not something a consumer of a release tarball wants.
set -eu

VERSION=3.6.5
PREFIX="${1:?usage: build_mbedtls.sh <install-prefix>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The release tarball, not the git tag: it ships the generated PSA sources, so
# the build needs no Python.
curl -sSfL -o "$WORK/mbedtls.tar.bz2" \
  "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$VERSION/mbedtls-$VERSION.tar.bz2"
tar xjf "$WORK/mbedtls.tar.bz2" -C "$WORK"

cmake -S "$WORK/mbedtls-$VERSION" -B "$WORK/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
  -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
  -DENABLE_TESTING=OFF \
  -DENABLE_PROGRAMS=OFF \
  -DMBEDTLS_FATAL_WARNINGS=OFF \
  ${CMAKE_EXTRA:-}
cmake --build "$WORK/build" --parallel
cmake --install "$WORK/build"
