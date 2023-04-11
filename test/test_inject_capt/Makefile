CPPFLAGS=-Wall -D _GNU_SOURCE
LDFLAGS=-lpcap 

all: test_inject_burst test_capt_burst  # test_inject_once test_capt_once

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

test_inject_burst: test_inject_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_capt_burst: test_capt_burst.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_inject_once: test_inject_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_capt_once: test_capt_once.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f test_inject_burst test_capt_busrt test_inject_once test_capt_once *~ *.o
