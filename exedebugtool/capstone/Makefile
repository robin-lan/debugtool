#CC = g++
#LIB = -L/data/protobuf/2.5.0_x64/lib/
#INC = -I/data/protobuf/2.5.0_x64/include/ -I./
#CCFLAGS = -DSNACC_DEEP_COPY -DHAVE_VARIABLE_SIZED_AUTOMATIC_ARRAYS -Wno-deprecated  -fPIC
#LIBPATH=/home/lanliqiang/worksrc/buildroot-2020.08.2/output/host/aarch64-buildroot-linux-uclibc/sysroot/usr/lib/

TARGET=debugtool

CFLAGS:=-DCAPSTONE_ARM64_SUPPORT -DCAPSTONE_HAS_ARM64

CSRC=$(wildcard ./*.c)
CXXSRC=$(wildcard ./*.cpp)

#COBJ=$(patsubst %.c, %.o, $(CSRC))
COBJ= cs.o Mapping.o MCInst.o MCInstrDesc.o MCRegisterInfo.o SStream.o utils.o AArch64BaseInfo.o AArch64Disassembler.o AArch64InstPrinter.o AArch64Mapping.o AArch64Module.o test_arm64.o
CXXOBJ=$(patsubst %.cpp, %.o, $(CXXSRC))

$(TARGET): $(COBJ) $(CXXOBJ)
	$(CC) $(CCFLAGS) -o $@ $^  $(LDFLAGS)
#    $(CC) $(CCFLAGS) -o $@ $^ $(LIB) -static ${LIBPATH}libc.a

$(COBJ):%.o: %.c
	$(CC) $(CFLAGS)  $(INC) -o $@ -c -g $<

$(CXXOBJ):%.o: %.cpp
	$(CXX) $(CCFLAGS)  $(INC) -o $@ -c -g $<

clean:
	rm -f *.o
	rm -f $(TARGET)
