CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: wifiraw #multi-aio-raw #aio-raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

wifiraw: wifiraw.o wifiraw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

multi-aio-raw: multi-aio-raw.o multi-aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

aio-raw: aio-raw.o aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wifiraw multi-aio-raw aio-raw *~ *.o
