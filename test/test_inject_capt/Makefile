#CPPFLAGS=-Wall -D _GNU_SOURCE -g -D LEGACY
CPPFLAGS=-Wall -D _GNU_SOURCE -g 
LDFLAGS=-lpcap 

all: inject_raw capt_raw # inject_pcap capt_pcap 
%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


inject_pcap: inject_pcap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

inject_raw: inject_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

capt_pcap: capt_pcap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

capt_raw: capt_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f capt_pcap inject_pcap capt_raw inject_raw *~ *.o
