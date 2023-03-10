#CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -g
LDFLAGS=-lpcap 


all: tx rx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f tx rx *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
