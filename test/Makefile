CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library
LDFLAGS=-lpcap 


all: reading sending sniffer tx rx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

reading: reading.o
	gcc -o $@ $^ $(LDFLAGS)

sending: sending.o
	gcc -o $@ $^ $(LDFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

sniffer: sniffer.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f reading sending sniffer rx tx *~ *.o ../radiotap-library/radiotap.o
#	rm -f reading sending sniffer *.o
