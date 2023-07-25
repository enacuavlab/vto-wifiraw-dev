#PROT := RAW

PROTFLAG := 
  ifneq ($(PROT),RAW)
    PROTFLAG += -DADDR_REMOTE_BOARD=\"192.168.3.2\"
    PROTFLAG += -DADDR_REMOTE_GROUND=\"192.168.3.1\"
  else
    PROTFLAG += -DRAW
  endif

CPPFLAGS=-Wall -D _GNU_SOURCE -g

all: wfb_tx_video wfb_rx_video

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS) $(PROTFLAG)

wfb_tx_video: wfb_tx_video.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

wfb_rx_video: wfb_rx_video.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wfb_tx_video wfb_rx_video *~ *.o
