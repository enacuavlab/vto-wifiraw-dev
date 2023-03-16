CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 

all: tx_fec rx_fec test_zfec

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

test_zfec: test_zfec.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f tx_fec rx_fec tx rx test_zfec  *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
