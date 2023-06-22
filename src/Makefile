CPPFLAGS=-Wall -D _GNU_SOURCE -g  -D RAW

all: mux

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

wifiraw-mux: mux.o 
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f mux *~ *.o
