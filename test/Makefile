CPPFLAGS=-Wall -D _GNU_SOURCE -I../zfec/zfec -g
LDFLAGS=-lpcap 

all: test_tx_fec # test_rx test_tx test_crc32 test_zfec_00 test_zfec_01 test_zfec_02 packetspammer

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

test_tx: test_tx_fec.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_tx: test_tx.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_rx: test_rx.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_zfec_00: test_zfec_00.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_01: test_zfec_01.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_02: test_zfec_02.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_crc32: test_crc32.o
	gcc -o $@ $^ $(LDFLAGS)

packetspammer: packetspammer.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f test_tx_fec test_tx test_rx test_zfec_00 test_zfec_01 test_zfec_02 test_crc32 packetspammer  *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
