#make -C /mnt/sda3/worksrc/app-player/android/out/target/product/generic_arm64/out_kernel ARCH=arm64  CROSS_COMPILE=/mnt/sda3/worksrc/app-player/android/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-android- LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=/mnt/sda3/worksrc/app-player/android/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin M=$(pwd)


#make -C /mnt/sdb1/buildroot/compile/linux-4.19.195 ARCH=arm64 CROSS_COMPILE=/mnt/sdb1/buildroot/buildroot-2020.08.2/output/host/bin/aarch64-linux- LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=/mnt/sdb1/buildroot/buildroot-2020.08.2/output/host/bin M=$(pwd)


#make -C /home/lanliqiang/worksrc/kernel64/obj/kernel ARCH=x86_64 CROSS_COMPILE=/home/lanliqiang/worksrc/app-player/android/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.11-4.6/bin/x86_64-linux- LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=/home/lanliqiang/worksrc/app-player/android/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.11-4.6/bin M=$(pwd)

export PATH=/home/lanliqiang/worksrc/berlin/module/toolchain/bin:$PATH
export ARCH=arm64
export CROSS_COMPILE=/home/lanliqiang/worksrc/berlin/module/toolchain/bin/aarch64-buildroot-linux-uclibc-
export LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=/home/lanliqiang/worksrc/berlin/module/toolchain/bin


make

cd ./exedebugtool

./build.sh
