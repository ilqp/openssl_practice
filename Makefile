# Quick instruction:
# To build against an OpenSSL built in the source tree, do this:
#
#    make OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../..
#
# To run the demos when linked with a shared library (default):
#
#    LD_LIBRARY_PATH=../.. ./aesccm
#    LD_LIBRARY_PATH=../.. ./aesgcm

CFLAGS = $(OPENSSL_INCS_LOCATION)
LDFLAGS = $(OPENSSL_LIBS_LOCATION) -lssl -lcrypto

define run
	# make -C build run_aes_gcm
	make -C build run_aes_256
endef

all: aesccm aesgcm

aesccm: aesccm.o
aesgcm: aesgcm.o

aesccm aesgcm:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

rbuild: build
	cd build && make

fbuild: clean
	mkdir build && cd build && cmake ../ && make

frun: fbuild
	$(call run)

rrun: rbuild
	$(call run)

clean:
	rm -rf build
