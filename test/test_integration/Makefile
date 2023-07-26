PROT := RAW

PROTFLAG := 
  ifneq ($(PROT),RAW)
    PROTFLAG += -DADDR_REMOTE_GROUND=\"192.168.3.1\"
  else
    PROTFLAG += -DRAW
  endif

CPPFLAGS=-Wall -D _GNU_SOURCE -g

all: test_rcv test_snd

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS) $(PROTFLAG)

test_rcv: test_rcv.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

test_snd: test_snd.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f test_rcv test_snd *~ *.o
