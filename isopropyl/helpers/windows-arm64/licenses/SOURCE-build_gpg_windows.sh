set -eu
export PATH=/build/llvm/bin:$PATH
for arch in x86_64 aarch64; do
 target=$arch-w64-mingw32
 prefix=/build/gpg-prefix-$arch
 export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
 export LDFLAGS=''
 for project in libgpg-error libgcrypt libassuan libksba npth; do
  case $project in
   libgpg-error) version=1.61;; libgcrypt) version=1.12.4;;
   libassuan) version=3.0.2;; libksba) version=1.6.8;; npth) version=1.8;;
  esac
  mkdir -p /build/gpg-$project-$arch
  tar -xjf /sources/$project-$version.tar.bz2 --strip-components=1 -C /build/gpg-$project-$arch
  cd /build/gpg-$project-$arch
  ./configure --host="$target" --prefix="$prefix" --disable-shared --enable-static --disable-nls --disable-doc --disable-asm --with-libgpg-error-prefix="$prefix" > /output/gpg-$project-$arch.log 2>&1
  make -j4 >> /output/gpg-$project-$arch.log 2>&1
  make install >> /output/gpg-$project-$arch.log 2>&1
 done
 mkdir -p /build/gpg-gnupg-$arch
 tar -xjf /sources/gnupg-2.5.24.tar.bz2 --strip-components=1 -C /build/gpg-gnupg-$arch
 cd /build/gpg-gnupg-$arch
 ./configure --host="$target" --prefix="$prefix" --with-libgpg-error-prefix="$prefix" --with-libgcrypt-prefix="$prefix" --with-libassuan-prefix="$prefix" --with-ksba-prefix="$prefix" --with-npth-prefix="$prefix" --disable-gpgsm --disable-scdaemon --disable-g13 --disable-dirmngr --disable-keyboxd --disable-tpm2d --disable-doc --disable-wks-tools --disable-nls --disable-sqlite --disable-gnutls --disable-ldap --disable-tests --without-readline > /output/gpg-gnupg-$arch.log 2>&1
 make -j4 -C common libcommon.a libcommonpth.a libgpgrl.a >> /output/gpg-gnupg-$arch.log 2>&1
 make -j4 -C kbx libkeybox.a >> /output/gpg-gnupg-$arch.log 2>&1
 make -j4 -C regexp libregexp.a >> /output/gpg-gnupg-$arch.log 2>&1
 make -j4 -C g10 gpgv.exe >> /output/gpg-gnupg-$arch.log 2>&1
 cp g10/gpgv.exe /output/windows-$arch/
done
