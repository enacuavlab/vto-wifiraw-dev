CPPFLAGS=-Wall -D _GNU_SOURCE -g

all: wifiraw-mux #wifiraw

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

wifiraw-mux: wifiraw-mux.o wifiraw-com-mux.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

wifiraw: wifiraw.o wifiraw-com.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wifiraw-mux wifiraw *~ *.o
