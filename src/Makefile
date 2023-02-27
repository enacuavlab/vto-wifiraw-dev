LDFLAGS=-lpcap
CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
#CPPFLAGS=-D _GNU_SOURCE -I../radiotap-library

all: rx tx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f rx tx *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
