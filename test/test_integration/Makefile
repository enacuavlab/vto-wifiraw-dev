CPPFLAGS=-Wall -D _GNU_SOURCE -g 

all: wfb_tx_video wfb_rx_video

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

wfb_tx_video: wfb_tx_video.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

wfb_rx_video: wfb_rx_video.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wfb_tx_video wfb_rx_video *~ *.o
