set -eu
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LIBS CC CXX AR RANLIB RC WINDRES PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv bison flex > /output/qemu-apt.log
python3 -m venv /build/qemu-build-python
/build/qemu-build-python/bin/pip install meson==1.9.1 ninja==1.13.0 tomli==2.2.1 > /output/qemu-pip.log
export PATH=/build/qemu-build-python/bin:/build/llvm/bin:$PATH
for arch in aarch64 x86_64; do
 target=${arch}-w64-mingw32
 prefix=/build/qemu-prefix-$arch
 mkdir -p "$prefix/lib/pkgconfig" "$prefix/include" /build/qemu-pcre-$arch /build/qemu-glib-$arch /build/qemu-source-$arch /build/qemu-build-$arch /build/qemu-zlib-$arch
 tar -xjf /sources/qemu-pcre2.tar.bz2 --strip-components=1 -C /build/qemu-pcre-$arch
 cd /build/qemu-pcre-$arch
 ./configure --host="$target" --prefix="$prefix" --disable-shared --enable-static --disable-pcre2grep --disable-pcre2test > /output/qemu-pcre-$arch.log 2>&1
 make -j4 >> /output/qemu-pcre-$arch.log 2>&1
 make install >> /output/qemu-pcre-$arch.log 2>&1
 tar -xzf /sources/qemu-zlib.tar.gz --strip-components=1 -C /build/qemu-zlib-$arch
 cd /build/qemu-zlib-$arch
 make -f win32/Makefile.gcc PREFIX="$target-" -j4 > /output/qemu-zlib-$arch.log 2>&1
 cp libz.a "$prefix/lib/"
 cp zlib.h zconf.h "$prefix/include/"
 cat > "$prefix/lib/pkgconfig/zlib.pc" <<EOF
prefix=$prefix
libdir=\${prefix}/lib
includedir=\${prefix}/include
Name: zlib
Description: zlib compression library
Version: 1.3.2
Libs: -L\${libdir} -lz
Cflags: -I\${includedir}
EOF
 mkdir -p /build/qemu-zstd-$arch
 tar -xzf /sources/qemu-zstd.tar.gz --strip-components=1 -C /build/qemu-zstd-$arch
 make -C /build/qemu-zstd-$arch/lib CC="$target-clang" AR="$target-ar" -j4 libzstd.a > /output/qemu-zstd-$arch.log 2>&1
 cp /build/qemu-zstd-$arch/lib/libzstd.a "$prefix/lib/"
 cp /build/qemu-zstd-$arch/lib/zstd.h /build/qemu-zstd-$arch/lib/zstd_errors.h "$prefix/include/"
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
 tar -xJf /sources/qemu-glib.tar.xz --strip-components=1 -C /build/qemu-glib-$arch
 cpu_family=$arch
 [ "$arch" != x86_64 ] || cpu_family=x86_64
 cat > /build/qemu-cross-$arch.ini <<EOF
[binaries]
c = '$target-clang'
cpp = '$target-clang++'
ar = '$target-ar'
strip = '$target-strip'
windres = '$target-windres'
pkg-config = 'pkg-config'
[host_machine]
system = 'windows'
cpu_family = '$cpu_family'
cpu = '$arch'
endian = 'little'
[properties]
needs_exe_wrapper = true
[built-in options]
c_args = ['-O2']
c_link_args = ['-static']
EOF
 PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig" meson setup /build/qemu-glib-build-$arch /build/qemu-glib-$arch --cross-file=/build/qemu-cross-$arch.ini --prefix="$prefix" --default-library=static --buildtype=release -Dtests=false -Dinstalled_tests=false -Dintrospection=disabled -Ddocumentation=false -Dman-pages=disabled -Dsysprof=disabled -Dlibmount=disabled -Dselinux=disabled -Dnls=disabled -Dforce_fallback_for=intl > /output/qemu-glib-$arch.log 2>&1
 ninja -C /build/qemu-glib-build-$arch -j4 >> /output/qemu-glib-$arch.log 2>&1
 ninja -C /build/qemu-glib-build-$arch install >> /output/qemu-glib-$arch.log 2>&1
 tar -xJf /sources/qemu-source.tar.xz --strip-components=1 -C /build/qemu-source-$arch --exclude='qemu-11.1.2/roms/*'
 cd /build/qemu-build-$arch
 "$target-windres" -I /sources /sources/windows_utf8.rc -o /build/qemu-utf8-$arch.o
 PKG_CONFIG=/usr/bin/pkg-config PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig" /build/qemu-source-$arch/configure --cross-prefix="$target-" --python=/build/qemu-build-python/bin/python --without-default-features --disable-system --disable-user --enable-tools --enable-vpc --enable-vhdx --enable-qcow1 --enable-zstd --disable-docs --static --extra-ldflags="/build/qemu-utf8-$arch.o" > /output/qemu-$arch.log 2>&1
 ninja -j4 qemu-img.exe qemu-io.exe >> /output/qemu-$arch.log 2>&1
 mkdir -p /output/windows-$arch
 cp qemu-img.exe qemu-io.exe /output/windows-$arch/
done
