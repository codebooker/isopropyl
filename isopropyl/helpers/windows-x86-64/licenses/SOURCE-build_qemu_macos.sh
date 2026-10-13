#!/bin/sh
# Build qemu-img/qemu-io for macOS ARM64 13+ with static GLib/PCRE/intl.
# Arguments: extracted source root (qemu,glib,pcre2,zstd), build root, install prefix.
set -eu
source_root=$(cd "$1" && pwd)
build_root=$2
prefix=$3
mkdir -p "$build_root" "$prefix/lib/pkgconfig"
export MACOSX_DEPLOYMENT_TARGET=13.0
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
export CFLAGS='-O2 -mmacosx-version-min=13.0'
export LDFLAGS='-mmacosx-version-min=13.0'
cd "$source_root/pcre2"
./configure --prefix="$prefix" --disable-shared --enable-static --disable-pcre2grep --disable-pcre2test
make -j4
make install
make -C "$source_root/zstd/lib" -j4 libzstd.a
cp "$source_root/zstd/lib/libzstd.a" "$prefix/lib/"
cp "$source_root/zstd/lib/zstd.h" "$source_root/zstd/lib/zstd_errors.h" "$prefix/include/"
cat > "$prefix/lib/pkgconfig/libzstd.pc" <<EOF
prefix=$prefix
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: zstd
Description: Zstandard compression library
Version: 1.5.7
Libs: -L\${libdir} -lzstd
Cflags: -I\${includedir}
EOF
sdk=$(xcrun --show-sdk-path)
cat > "$prefix/lib/pkgconfig/libffi.pc" <<EOF
prefix=$sdk/usr
libdir=\${prefix}/lib
includedir=\${prefix}/include/ffi
Name: libffi
Description: macOS SDK libffi
Version: 3.4.0
Libs: -lffi
Cflags: -I\${includedir}
EOF
meson setup "$build_root/glib" "$source_root/glib" --prefix="$prefix" --default-library=static --buildtype=release "-Dobjc_args=['-O2','-mmacosx-version-min=13.0']" "-Dobjc_link_args=['-mmacosx-version-min=13.0']" -Dtests=false -Dinstalled_tests=false -Dintrospection=disabled -Ddocumentation=false -Dman-pages=disabled -Dsysprof=disabled -Dlibmount=disabled -Dselinux=disabled -Dnls=disabled -Dforce_fallback_for=intl
# SDK 27 exposes pipe2 as weak on earlier systems; GLib's link probe
# otherwise enables it even for deployment target 13. Use the portable fallback.
sed -i '' 's/#define HAVE_PIPE2 1/#undef HAVE_PIPE2/' "$build_root/glib/config.h"
ninja -C "$build_root/glib" -j4
ninja -C "$build_root/glib" install
mkdir -p "$build_root/qemu"
cd "$build_root/qemu"
"$source_root/qemu/configure" --without-default-features --disable-system --disable-user --enable-tools --enable-vpc --enable-vhdx --enable-qcow1 --enable-zstd --disable-docs --extra-cflags='-O2 -mmacosx-version-min=13.0' --extra-ldflags="-mmacosx-version-min=13.0 -L$prefix/lib"
ninja -j4 qemu-img qemu-io
otool -L qemu-img
otool -l qemu-img | sed -n '/LC_BUILD_VERSION/,+5p'
