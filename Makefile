CC = x86_64-w64-mingw32-g++
CXXFLAGS = -O2 -fpermissive
LIBS = -lole32 -loleaut32 -luuid -lwtsapi32 -lws2_32 -lshlwapi -lcrypt32 -lsecur32
LDFLAGS_STATIC = -static -s
LDFLAGS_DYNAMIC = -s
SRC = tgtdeleg.cpp

all: tgtdeleg_static.exe

tgtdeleg_static.exe: $(SRC)
	$(CC) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS_STATIC) $(LIBS)

tgtdeleg_dynamic.exe: $(SRC)
	$(CC) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS_DYNAMIC) -static-libgcc -static-libstdc++ $(LIBS)

clean:
	rm -f tgtdeleg_static.exe tgtdeleg_dynamic.exe
