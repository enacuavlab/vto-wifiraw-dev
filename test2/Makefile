CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 

all: test_zfec_00 test_zfec_01 test_zfec_02

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx_fec: tx_fec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_fec: rx_fec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_zfec_00: test_zfec_00.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_01: test_zfec_01.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec_02: test_zfec_02.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f tx_fec rx_fec tx rx test_zfec_00 test_zfec_01 test_zfec_02  *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
