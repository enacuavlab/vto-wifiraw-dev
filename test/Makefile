CPPFLAGS=-Wall -D _GNU_SOURCE
#CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library


all: reading sending

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

reading: reading.o
	gcc -o $@ $^ $(LDFLAGS)

sending: sending.o
	gcc -o $@ $^ $(LDFLAGS)


#rx: rx.o ../radiotap-library/radiotap.o
#        gcc -o $@ $^ $(LDFLAGS)

#tx: tx.o ../radiotap-library/radiotap.o
#        gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f reading sending *.o
#        rm -f rx tx *~ *.o ../radiotap-library/radiotap.o

