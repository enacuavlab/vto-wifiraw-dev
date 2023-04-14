CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: test_pcap_inject_once test_pcap_inject_burst test_pcap_capt_once test_pcap_capt_burst test_raw_inject_once test_raw_inject_burst test_raw_capt_once test_raw_capt_burst

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

test_raw_inject_once: test_raw_inject_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_raw_inject_burst: test_raw_inject_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_raw_capt_once: test_raw_capt_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_raw_capt_burst: test_raw_capt_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_pcap_inject_once: test_pcap_inject_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_pcap_inject_burst: test_pcap_inject_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_pcap_capt_once: test_pcap_capt_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_pcap_capt_burst: test_pcap_capt_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f test_pcap_inject_once test_pcap_inject_burst test_pcap_capt_once test_pcap_capt_burst test_raw_inject_once test_raw_inject_burst test_raw_capt_once test_raw_capt_burst *~ *.o
