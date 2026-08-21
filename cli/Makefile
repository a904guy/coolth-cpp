# The command line tool. Needs libcurl for the cloud commands; without it the
# LAN commands still build and work.
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unused-parameter -O2
LDLIBS := -lmbedcrypto
SRC := main.cpp net_posix.cpp \
       ../components/coolth/protocol.cpp ../components/coolth/discovery.cpp \
       ../components/coolth/cloud.cpp ../components/coolth/cloud_lan.cpp \
       ../components/coolth/json_lite.cpp ../components/coolth/properties.cpp \
       ../components/coolth/capabilities.cpp ../components/coolth/device_cc.cpp \
       ../components/coolth/lan.cpp

HAVE_CURL := $(shell pkg-config --exists libcurl && echo yes)
ifeq ($(HAVE_CURL),yes)
CXXFLAGS += -DCOOLTH_HAVE_CURL $(shell pkg-config --cflags libcurl)
LDLIBS += $(shell pkg-config --libs libcurl)
endif

coolth-cpp: $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

.PHONY: clean
clean:
	rm -f coolth-cpp
