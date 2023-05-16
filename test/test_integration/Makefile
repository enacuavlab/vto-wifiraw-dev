CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: tx_udp #tx_raw rx_raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx_udp: tx_udp.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

tx_raw: tx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_raw: rx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f tx_udp tx_raw rx_raw *~ *.o
