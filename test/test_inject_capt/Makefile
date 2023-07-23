#CPPFLAGS=-Wall -D _GNU_SOURCE -g -D LEGACY
CPPFLAGS=-Wall -D _GNU_SOURCE -g 

all: inject_raw capt_raw
%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

inject_raw: inject_raw.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f inject_raw capt_raw *~ *.o
