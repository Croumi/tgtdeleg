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

# Build-time randomization: XOR key (0x10-0xFE, avoids 0x00 and low values)
RAND_XOR_KEY = $(shell printf '%02X' $$(( (RANDOM % 239) + 16 )))

# Post-build: sanitize PE headers (remove compiler fingerprints)
SANITIZE = @python3 sanitize_pe.py $@

all: tgtdeleg_static.exe

tgtdeleg_static.exe: $(SRC)
	$(eval XOR_KEY := $(RAND_XOR_KEY))
	@echo "[*] Building $@ (XOR: 0x$(XOR_KEY))"
	@cp $(SRC) _tgtdeleg_temp.cpp
	@sed -i 's/__XOR_KEY__/$(XOR_KEY)/g' _tgtdeleg_temp.cpp
	$(CC) $(CXXFLAGS) -o $@ _tgtdeleg_temp.cpp -Wl,-e,TgtDelegEntry $(LDFLAGS_STATIC) $(LIBS)
	@rm _tgtdeleg_temp.cpp
	$(SANITIZE)

tgtdeleg_dynamic.exe: $(SRC)
	$(eval XOR_KEY := $(RAND_XOR_KEY))
	@echo "[*] Building $@ (XOR: 0x$(XOR_KEY))"
	@cp $(SRC) _tgtdeleg_temp_dyn.cpp
	@sed -i 's/__XOR_KEY__/$(XOR_KEY)/g' _tgtdeleg_temp_dyn.cpp
	$(CC) $(CXXFLAGS) -o $@ _tgtdeleg_temp_dyn.cpp -Wl,-e,TgtDelegEntry $(LDFLAGS_DYNAMIC) $(LIBS)
	@rm _tgtdeleg_temp_dyn.cpp
	$(SANITIZE)

clean:
	rm -f tgtdeleg_static.exe tgtdeleg_dynamic.exe _tgtdeleg_temp*.cpp
