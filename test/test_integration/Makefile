CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: aio-raw #tx_udp_dbg rx_udp_dbg # tx_dbg rx_dbg # tx_udp rx_udp #tx_raw rx_raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

aio-raw: aio-raw.o aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

rx_udp_dbg: rx_udp_dbg.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

tx_udp_dbg: tx_udp_dbg.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

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
	rm -f aio-raw rx_udp_dbg  tx_udp_dbg  rx_dbg tx_dbg  tx_udp rx_udp tx_raw rx_raw *~ *.o
