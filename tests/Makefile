# Host build of the library. mbedtls is the same library ESP-IDF ships, so
# bytes that match here match on the device too.
CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unused-parameter -O1 -g
LDLIBS := -lmbedcrypto

LIB := $(wildcard ../components/coolth/*.cpp)
TESTS := test_protocol test_discovery_cloud test_control test_cloud_lan \
         test_device_cc test_lan

$(TESTS): %: %.cpp $(LIB) harness.h golden_vectors.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB) $(LDLIBS)

.PHONY: all check vectors reference clean
all: $(TESTS)

check: $(TESTS)
	@fail=0; for t in $(TESTS); do echo; echo "== $$t =="; ./$$t || fail=1; done; exit $$fail

# Regenerate the golden vectors from coolth, the Python reference.
vectors: | ../reference
	../../.venv/bin/python ../tools/golden_vectors.py

# coolth's source, vendored so vectors can be regenerated. Not committed --
# it belongs to its own repository.
../reference reference:
	mkdir -p ../reference
	curl -sL https://github.com/a904guy/coolth-ac-controller/tarball/main \
	  | tar xz -C ../reference --strip-components=1 --wildcards '*/coolth'

clean:
	rm -f $(TESTS)
