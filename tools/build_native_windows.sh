#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run inside Ubuntu22.04 ARM64 with /sources verified by
# download_native_sources.py; /build persistent and /output for artifacts.
set -eu
export DEBIAN_FRONTEND=noninteractive
if [ -f /build/llvm/bin/clang ]; then skip_setup=yes; else skip_setup=no; fi
if [ "$skip_setup" = no ]; then
apt-get update -qq
apt-get install -y -qq build-essential autoconf automake libtool pkg-config gettext python3 libgcrypt20-dev xz-utils zlib1g-dev > /tmp/apt.log
mkdir -p /build/llvm
 tar -xJf /sources/llvm-mingw.tar.xz --strip-components=1 -C /build/llvm
fi
export PATH=/build/llvm/bin:$PATH
failed=0
for arch in x86_64 aarch64; do
 target=${arch}-w64-mingw32
 prefix=/output/windows-${arch}
 mkdir -p "$prefix" /build/e2fs-$arch /build/ntfs-$arch /build/wim-$arch
 "$target-windres" -I/sources /sources/windows_utf8.rc -O coff -o "$prefix/windows_utf8.o"
 export LDFLAGS="$prefix/windows_utf8.o"
 build_e2fs() {
 rm -rf /build/e2fs-$arch || return $?
 mkdir -p /build/e2fs-$arch || return $?
 tar -xzf /sources/e2fsprogs.tar.gz --strip-components=1 -C /build/e2fs-$arch || return $?
 python3 /sources/port_e2fs.py /build/e2fs-$arch || return $?
 cd /build/e2fs-$arch || return $?
 CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__USE_MINGW_ALARM" ./configure --host="$target" --disable-nls --disable-elf-shlibs --disable-bsd-shlibs --disable-fuse2fs --enable-libblkid --enable-libuuid --disable-mmp --disable-quota > /output/e2fs-$arch.log 2>&1 || return $?
 make -j4 -C lib/et CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__USE_MINGW_ALARM -include /sources/win_file_abi.h" >> /output/e2fs-$arch.log 2>&1 || return $?
 make -C lib/ext2fs ext2_err.h >> /output/e2fs-$arch.log 2>&1 || return $?
 for lib in et uuid blkid e2p ext2fs support; do make -j4 -C lib/$lib CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__USE_MINGW_ALARM -include /sources/win_file_abi.h" >> /output/e2fs-$arch.log 2>&1 || return $?; done || return $?
 make -j4 -C misc mke2fs CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__USE_MINGW_ALARM -include /sources/win_file_abi.h" >> /output/e2fs-$arch.log 2>&1 || return $?
 cp misc/mke2fs.exe "$prefix/" || return $?
 }
 build_e2fs || { failed=1; echo "FAILED e2fs $arch" >&2; }
 build_ntfs() {
 rm -rf /build/ntfs-$arch || return $?
 mkdir -p /build/ntfs-$arch || return $?
 tar -xzf /sources/ntfs-3g.tar.gz --strip-components=1 -C /build/ntfs-$arch || return $?
 python3 /sources/port_ntfs.py /build/ntfs-$arch || return $?
 cd /build/ntfs-$arch || return $?
 sed -i 's@#include <pwd.h>@#include "win_posix_accounts.h"@; /#include <grp.h>/d' libntfs-3g/acls.c libntfs-3g/security.c || return $?
 cp /sources/win_posix_accounts.h libntfs-3g/ || return $?
 cp /sources/win_regular_io.c libntfs-3g/win32_io.c || return $?
 sed -i 's/INDEX_TYPE_ROOT, ir, ie/INDEX_TYPE_ROOT, (index_union){.ir=ir}, ie/g; s/INDEX_TYPE_ALLOCATION, ia, ie/INDEX_TYPE_ALLOCATION, (index_union){.ia=ia}, ie/g' libntfs-3g/dir.c || return $?
 sed -i 's/sbuf.st_blocks/0/g' ntfsprogs/mkntfs.c || return $?
 sed -i 's/, args);/, ##args);/g' ntfsprogs/utils.h || return $?
 sed -i '/#include <syslog.h>/d' libntfs-3g/ioctl.c || return $?
 ./autogen.sh > /output/ntfs-$arch.log 2>&1 || return $?
 CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__timespec_defined -include /sources/win_posix_accounts.h" ./configure --host="$target" --disable-ntfs-3g --disable-plugins --disable-nfconv --disable-shared --enable-static --without-hd >> /output/ntfs-$arch.log 2>&1 || return $?
 "$target-clang" -D_FILE_OFFSET_BITS=64 -D__timespec_defined -include /sources/win_file_abi.h -I. -Iinclude -c /sources/ntfs_abi_check.c -o "$prefix/ntfs-abi-check.o" >> /output/ntfs-$arch.log 2>&1 || return $?
 make -j4 -C libntfs-3g LDFLAGS="" CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__timespec_defined -include /sources/win_file_abi.h -include /sources/win_posix_accounts.h" >> /output/ntfs-$arch.log 2>&1 || return $?
 make -j4 -C ntfsprogs mkntfs.exe ntfscp.exe ntfscat.exe CFLAGS="-O2 -D_FILE_OFFSET_BITS=64 -D__timespec_defined -include /sources/win_file_abi.h -include /sources/win_posix_accounts.h" >> /output/ntfs-$arch.log 2>&1 || return $?
 cp ntfsprogs/mkntfs.exe ntfsprogs/ntfscp.exe ntfsprogs/ntfscat.exe "$prefix/" || return $?
 "$target-clang" -O2 -D_FILE_OFFSET_BITS=64 -include /sources/win_file_abi.h -D__timespec_defined -I. -Iinclude /sources/ntfs-tree.c libntfs-3g/.libs/libntfs-3g.a "$prefix/windows_utf8.o" -o "$prefix/ntfs-tree.exe" || return $?
 }
 build_ntfs || { failed=1; echo "FAILED ntfs $arch" >&2; }
 build_wim() {
 tar -xzf /sources/wimlib.tar.gz --strip-components=1 -C /build/wim-$arch || return $?
 cd /build/wim-$arch || return $?
 ./bootstrap > /output/wim-$arch.log 2>&1 || return $?
 LDFLAGS="" ./configure --host="$target" --disable-shared --enable-static --without-fuse --without-ntfs-3g >> /output/wim-$arch.log 2>&1 || return $?
 make -j4 >> /output/wim-$arch.log 2>&1 || return $?
 cp wimlib-imagex.exe "$prefix/" || return $?
 }
 build_wim || { failed=1; echo "FAILED wim $arch" >&2; }
 build_udf() {
 mkdir -p /build/udf-$arch || return $?
 tar -xzf /sources/udftools.tar.gz --strip-components=1 -C /build/udf-$arch || return $?
 python3 /sources/port_udftools.py /build/udf-$arch || return $?
 cd /build/udf-$arch || return $?
 "$target-clang" -O2 -municode -Iinclude mkudffs/main.c mkudffs/mkudffs.c mkudffs/defaults.c mkudffs/file.c mkudffs/options.c libudffs/crc.c libudffs/extent.c libudffs/misc.c libudffs/unicode.c -lbcrypt -o "$prefix/mkudffs.exe" > /output/udf-$arch.log 2>&1 || return $?
 }
 build_udf || { failed=1; echo "FAILED udf $arch" >&2; }
done


sh /sources/build_gpg_windows.sh || { failed=1; echo "FAILED gpg cross" >&2; }
sh /sources/build_qemu_windows.sh || { failed=1; echo "FAILED qemu cross" >&2; }
exit "$failed"
