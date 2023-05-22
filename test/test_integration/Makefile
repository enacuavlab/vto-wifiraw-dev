CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: multi-aio-raw #aio-raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

multi-aio-raw: multi-aio-raw.o multi-aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

aio-raw: aio-raw.o aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f multi-aio-raw aio-raw *~ *.o
