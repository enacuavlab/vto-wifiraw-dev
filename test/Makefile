CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 


#all: reading sending sniffer tx rx tx_fec
all: tx_fec rx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

reading: reading.o
	gcc -o $@ $^ $(LDFLAGS)

sending: sending.o
	gcc -o $@ $^ $(LDFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

sniffer: sniffer.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

tx_fec: tx_fec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f reading sending sniffer rx tx tx_fec *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
#	rm -f reading sending sniffer *.o
