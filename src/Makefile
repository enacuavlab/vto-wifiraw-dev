CPPFLAGS=-Wall -D _GNU_SOURCE -g
#LDFLAGS=-lpcap 

all: wifiraw-mux #wifiraw #multi-aio-raw #aio-raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

wifiraw-mux: wifiraw-mux.o wifiraw-com-mux.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

wifiraw: wifiraw.o wifiraw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

multi-aio-raw: multi-aio-raw.o multi-aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

aio-raw: aio-raw.o aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wifiraw-mux wifiraw multi-aio-raw aio-raw *~ *.o
