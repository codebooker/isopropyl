#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Sources are verified by tools/download_native_sources.py before extraction.
# Usage: build_filesystems_macos.sh SOURCE_ARCHIVES BUILD_DIRECTORY OUTPUT
set -eu
sources=$(cd "$1" && pwd)
mkdir -p "$2" "$3"
build=$(cd "$2" && pwd)
output=$(cd "$3" && pwd)
export MACOSX_DEPLOYMENT_TARGET=13.0
export CFLAGS='-O2 -mmacosx-version-min=13.0'
export LDFLAGS='-mmacosx-version-min=13.0'
mkdir -p "$build/ntfs" "$build/e2fs" "$build/e2fs-output" "$build/tsk" "$build/wim" "$build/7zip" "$build/udf"
tar -xzf "$sources/ntfs-3g.tar.gz" --strip-components=1 -C "$build/ntfs"
cd "$build/ntfs"
./autogen.sh
./configure --disable-ntfs-3g --disable-plugins --disable-nfconv --disable-shared --enable-static --without-hd
make -j4 -C libntfs-3g
make -j4 -C ntfsprogs mkntfs ntfscp ntfscat
clang -O2 -mmacosx-version-min=13.0 -I. -Iinclude "$sources/ntfs-tree.c" libntfs-3g/.libs/libntfs-3g.a -o "$output/ntfs-tree"
cp ntfsprogs/mkntfs ntfsprogs/ntfscp ntfsprogs/ntfscat "$output/"
tar -xzf "$sources/e2fsprogs.tar.gz" --strip-components=1 -C "$build/e2fs"
cd "$build/e2fs-output"
"$build/e2fs/configure" --disable-nls --disable-elf-shlibs --disable-bsd-shlibs --disable-fuse2fs --enable-libblkid --enable-libuuid --disable-mmp
make -j4 LDFLAGS='-mmacosx-version-min=13.0'
cp misc/mke2fs e2fsck/e2fsck debugfs/debugfs "$output/"
tar -xzf "$sources/sleuthkit.tar.gz" --strip-components=1 -C "$build/tsk"
cd "$build/tsk"
./configure --disable-shared --enable-static --disable-java --without-libewf --without-afflib --without-libvmdk --without-libvhdi
make -j4
cp tools/fstools/fls tools/fstools/icat tools/fstools/fsstat "$output/"
tar -xzf "$sources/wimlib.tar.gz" --strip-components=1 -C "$build/wim"
cd "$build/wim"
./bootstrap
./configure --disable-shared --enable-static --without-fuse --without-ntfs-3g
make -j4
cp wimlib-imagex "$output/"
tar -xJf "$sources/7zip.tar.xz" -C "$build/7zip"
cd "$build/7zip/CPP/7zip/Bundles/Alone2"
make -j4 -f ../../cmpl_mac_arm64.mak MY_ARCH='-arch arm64 -mmacosx-version-min=13.0'
cp b/m_arm64/7zz "$output/"
tar -xzf "$sources/udftools.tar.gz" --strip-components=1 -C "$build/udf"
python3 "$sources/port_udftools.py" "$build/udf"
cd "$build/udf"
clang -O2 -mmacosx-version-min=13.0 -Iinclude mkudffs/main.c mkudffs/mkudffs.c mkudffs/defaults.c mkudffs/file.c mkudffs/options.c libudffs/crc.c libudffs/extent.c libudffs/misc.c libudffs/unicode.c -o "$output/mkudffs"
