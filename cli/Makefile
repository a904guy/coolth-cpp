# The command line tool. Needs mbedtls -- the same library the protocol code
# already uses -- and nothing else, so a released binary can be a single
# statically linked file on every platform.
#
#   make                          against the system mbedtls
#   make STATIC=1                 no runtime dependencies
#   make MBEDTLS_PREFIX=/opt/mb   against a self-built mbedtls
#   make ARCHFLAGS="-arch arm64 -arch x86_64"    a macOS universal binary
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unused-parameter -O2
# mbedtls first, mbedcrypto last: static linking resolves left to right.
LDLIBS := -lmbedtls -lmbedx509 -lmbedcrypto
SRC := main.cpp net.cpp https.cpp \
       ../components/coolth/protocol.cpp ../components/coolth/discovery.cpp \
       ../components/coolth/cloud.cpp ../components/coolth/cloud_lan.cpp \
       ../components/coolth/json_lite.cpp ../components/coolth/properties.cpp \
       ../components/coolth/capabilities.cpp ../components/coolth/device_cc.cpp \
       ../components/coolth/lan.cpp

# An mbedtls built from source rather than installed by the distribution.
ifdef MBEDTLS_PREFIX
CXXFLAGS += -I$(MBEDTLS_PREFIX)/include
LDFLAGS += -L$(MBEDTLS_PREFIX)/lib
endif

# Ask the compiler what it targets, so this works when cross compiling too.
TRIPLE := $(shell $(CXX) -dumpmachine)
ifneq (,$(findstring mingw,$(TRIPLE)))
EXE := .exe
# Winsock, and the CRNG mbedtls seeds its entropy pool from.
LDLIBS += -lws2_32 -lbcrypt -ladvapi32
endif

ifdef STATIC
LDFLAGS += -static
endif

# Both arches in one Mach-O, for the macOS universal build.
CXXFLAGS += $(ARCHFLAGS)
LDFLAGS += $(ARCHFLAGS)

coolth-cpp$(EXE): $(SRC) ca_bundle.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f coolth-cpp coolth-cpp.exe
