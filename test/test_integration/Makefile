CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: tx_dbg rx_dbg # tx_udp rx_udp #tx_raw rx_raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

tx_dbg: tx_dbg.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_dbg: rx_dbg.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

tx_udp: tx_udp.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_udp: rx_udp.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

tx_raw: tx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_raw: rx_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f rx_dbg tx_dbg  tx_udp rx_udp tx_raw rx_raw *~ *.o
