export PATH=/home/lanliqiang/worksrc/berlin/module/toolchain/usr/bin:$PATH

# Tell configure what tools to use.
target_host=aarch64-buildroot-linux-uclibc
export AR=$target_host-ar
export AS=$target_host-as
export CC=$target_host-gcc
export CXX=$target_host-g++
export LD=$target_host-ld
export STRIP=$target_host-strip

export CFLAGS="-fPIE -fPIC -static " 
export LDFLAGS="-pie -static"

whereis ${CC}

# Tell configure what flags Android requires.
make
