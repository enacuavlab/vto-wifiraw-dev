FECPATH=../../zfec/zfec
CPPFLAGS=-Wall -D _GNU_SOURCE -I$(FECPATH) -g
LDFLAGS=-lpcap 

all: test_crc32 test_zfec_00 test_zfec_01 test_zfec_02

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

$(FECPATH)/fec.o: $(FECPATH)/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

test_zfec_00: test_zfec_00.o $(FECPATH)/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_01: test_zfec_01.o $(FECPATH)/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_02: test_zfec_02.o $(FECPATH)/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_crc32: test_crc32.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f test_zfec_00 test_zfec_01 test_zfec_02 test_crc32 *~ *.o $(FECPATH)/fec.o
