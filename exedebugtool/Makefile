#CC = g++
#LIB = -L/data/protobuf/2.5.0_x64/lib/
#INC = -I/data/protobuf/2.5.0_x64/include/ -I./
#INC=-I/home/lanliqiang/worksrc/berlin/module/toolchain/aarch64-buildroot-linux-uclibc/sysroot/usr/include
#CCFLAGS = -DSNACC_DEEP_COPY -DHAVE_VARIABLE_SIZED_AUTOMATIC_ARRAYS -Wno-deprecated  -fPIC
#LIBPATH=/home/lanliqiang/worksrc/buildroot-2020.08.2/output/host/aarch64-buildroot-linux-uclibc/sysroot/usr/lib/

TARGET=debugtool

CAPSTONE_DIR=./capstone
CSRC=$(wildcard $(CAPSTONE_DIR)/*.c ./*.c)
CXXSRC=$(wildcard ./*.cpp)

COBJ=$(patsubst %.c, %.o, $(CSRC))
CXXOBJ=$(patsubst %.cpp, %.o, $(CXXSRC))

CFLAGS:=-DCAPSTONE_ARM64_SUPPORT -DCAPSTONE_HAS_ARM64 -DUSER_INCLUDE


$(TARGET): $(COBJ) $(CXXOBJ)
	$(CC) $(CCFLAGS) -o $@ $^  $(LDFLAGS)
#	$(CC) $(CCFLAGS) -o $@ $^ $(LIB) -static ${LIBPATH}libc.a

$(COBJ):%.o: %.c
	$(CC) $(CFLAGS)  $(INC) -o $@ -c -g $<

$(CXXOBJ):%.o: %.cpp
	$(CXX) $(CCFLAGS)  $(INC) -o $@ -c -g $<

clean:
	rm -f *.o ./capstone/*.o
	rm -f $(TARGET)

