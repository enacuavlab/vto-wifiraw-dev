CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: capt_pcap inject_pcap
%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


inject_pcap: inject_pcap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

capt_pcap: capt_pcap.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f capt_pcap inject_pcap *~ *.o
