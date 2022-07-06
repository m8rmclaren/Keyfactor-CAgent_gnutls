# Configuring Keyfactor C-Agent for use with GNUTLS on Ubuntu 20.04 LTS

## Install dependencies
Before installing GNU TLS, dependencies need to be installed first. Many of the packages below come stock with momast Debian distributions, but it's worth running these installs anyway.
```bash
sudo apt install -y dash git-core autoconf libtool gettext autopoint
sudo apt install -y automake autogen nettle-dev libp11-kit-dev libtspi-dev libunistring-dev
sudo apt install -y guile-2.2-dev libtasn1-6-dev libidn2-0-dev gawk gperf
sudo apt install -y libunbound-dev dns-root-data bison gtk-doc-tools
sudo apt install -y texinfo texlive texlive-generic-recommended texlive-extra-utils
```


## Install libgnutls
The current stable release for GNU TLS is version 3.6. Download the latest stable version at [this link](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/).
```bash
wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.16.tar.xz
```
Unarchive the directory.
```bash
tar -xf gnutls-3.6.16.tar.xz
```
Run the following commands to install the library.
```bash
cd gnutls-<version>
./configure --prefix=/usr --with-included-unistring --with-included-libtasn1
make
make check
sudo make install
```