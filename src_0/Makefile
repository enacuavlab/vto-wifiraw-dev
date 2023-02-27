LDFLAGS=-lrt -lpcap
CPPFLAGS=-Wall -D _GNU_SOURCE

all: rx tx channelscan

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

channelscan: channelscan.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f rx tx channelscan *~ *.o
