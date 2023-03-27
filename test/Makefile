CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 

all: test_rx test_tx # test_zfec_00 test_zfec_01 test_zfec_02

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

test_tx: test_tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_rx: test_rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_zfec_00: test_zfec_00.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_01: test_zfec_01.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_02: test_zfec_02.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f test_tx test_rx test_zfec_00 test_zfec_01 test_zfec_02  *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
