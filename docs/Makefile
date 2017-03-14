HEADERS_DIR := $(ANDROID_BUILD_TOP)/out/soong/ndk/sysroot/usr/include

# This is wrong, but there isn't a good recursive wildcard in make. Integrate
# into the real build and just depend on the "ndk" target.
HEADERS := $(wildcard $(HEADERS_DIR)/*.h)

all: html

html: $(HEADERS) Doxyfile
	mkdir -p html
	( cat Doxyfile; echo "INPUT=$(HEADERS_DIR)" ) | doxygen -

clean:
	rm -rf html
.PHONY: clean
