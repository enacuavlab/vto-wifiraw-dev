CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 

all: tx_fec tx rx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx_fec: tx_fec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f tx_fec tx rx *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
