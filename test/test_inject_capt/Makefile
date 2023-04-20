CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: capt_80211 inject_80211 # test_pcap_inject_once test_pcap_inject_burst test_pcap_capt_once test_pcap_capt_burst test_raw_inject_once test_raw_inject_burst test_raw_capt_once test_raw_capt_burst

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

capt_80211: capt_80211.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

inject_80211: inject_80211.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

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
	rm -f capt_80211 inject_80211 test_pcap_inject_once test_pcap_inject_burst test_pcap_capt_once test_pcap_capt_burst test_raw_inject_once test_raw_inject_burst test_raw_capt_once test_raw_capt_burst *~ *.o
