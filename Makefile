CC = x86_64-w64-mingw32-g++
CXXFLAGS = -O2 -std=c++17 -fpermissive -nostartfiles -fno-exceptions -fno-rtti \
           -fno-tree-loop-distribute-patterns -fno-stack-protector -fno-ident \
           -ffunction-sections -fdata-sections
LDFLAGS_HARDEN = -Wl,--gc-sections -Wl,--no-insert-timestamp \
                 -Wl,--dynamicbase,--nxcompat,--high-entropy-va,--tsaware
LIBS = -lsecur32 -ladvapi32 -lkernel32
LDFLAGS_STATIC = -static -s $(LDFLAGS_HARDEN)
LDFLAGS_DYNAMIC = -s $(LDFLAGS_HARDEN)
SRC = tgtdeleg.cpp

# Generated XOR key header (random 16 bytes, unique per binary)
XOR_KEY_HDR = xor_key.gen.h
GEN_XOR_KEY = @python3 -c "import os; bs=os.urandom(16); print('constexpr unsigned char XKEY[] = {' + ','.join(f'0x{b:02x}' for b in bs) + '};'); print('constexpr size_t XKEY_LEN = sizeof(XKEY);')"

# Post-build: sanitize PE headers (remove compiler fingerprints)
SANITIZE = @python3 sanitize_pe.py $@

all: tgtdeleg_static.exe

tgtdeleg_static.exe: $(SRC)
	$(GEN_XOR_KEY) > $(XOR_KEY_HDR)
	@echo "[*] Building $@..."
	$(CC) $(CXXFLAGS) -o $@ $(SRC) -Wl,-e,TgtDelegEntry $(LDFLAGS_STATIC) $(LIBS)
	$(SANITIZE)

tgtdeleg_dynamic.exe: $(SRC)
	$(GEN_XOR_KEY) > $(XOR_KEY_HDR)
	@echo "[*] Building $@..."
	$(CC) $(CXXFLAGS) -o $@ $(SRC) -Wl,-e,TgtDelegEntry $(LDFLAGS_DYNAMIC) $(LIBS)
	$(SANITIZE)

clean:
	rm -f tgtdeleg_static.exe tgtdeleg_dynamic.exe $(XOR_KEY_HDR)

.PHONY: all clean
