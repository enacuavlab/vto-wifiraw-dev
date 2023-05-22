CPPFLAGS=-Wall -D _GNU_SOURCE -g
LDFLAGS=-lpcap 

all: aio-raw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

aio-raw: aio-raw.o aio-raw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f aio-raw *~ *.o
