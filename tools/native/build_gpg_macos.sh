set -eu
prefix=/tmp/isopropyl-mac-gpg/prefix
export MACOSX_DEPLOYMENT_TARGET=13.0
export CFLAGS='-O2 -mmacosx-version-min=13.0'
export LDFLAGS='-mmacosx-version-min=13.0'
export PATH="$prefix/bin:$PATH"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
for project in libgcrypt libassuan libksba npth; do
 cd /tmp/isopropyl-mac-gpg/$project
 ./configure --prefix="$prefix" --disable-shared --enable-static --disable-nls --disable-doc --disable-asm > /tmp/isopropyl-gpg-$project.log 2>&1
 make -j4 >> /tmp/isopropyl-gpg-$project.log 2>&1
 make install >> /tmp/isopropyl-gpg-$project.log 2>&1
done
cd /tmp/isopropyl-mac-gpg/gnupg
./configure --prefix="$prefix" --disable-gpgsm --disable-scdaemon --disable-g13 --disable-dirmngr --disable-keyboxd --disable-tpm2d --disable-doc --disable-wks-tools --disable-nls --disable-sqlite --disable-gnutls --disable-ldap --disable-tests > /tmp/isopropyl-gpg-gnupg.log 2>&1
make -j4 -C common libcommon.a >> /tmp/isopropyl-gpg-gnupg.log 2>&1
make -j4 -C kbx libkeybox.a >> /tmp/isopropyl-gpg-gnupg.log 2>&1
make -j4 -C g10 gpgv >> /tmp/isopropyl-gpg-gnupg.log 2>&1
