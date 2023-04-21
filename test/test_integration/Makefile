CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: tx_raw rx_raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx_raw: tx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_raw: rx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f tx_raw rx_raw *~ *.o
