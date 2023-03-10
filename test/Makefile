#CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../EZ-WifiBroadcast/wifibroadcast -g
CPPFLAGS=-Wall -D _GNU_SOURCE -I../radiotap-library -I../zfec/zfec -g
LDFLAGS=-lpcap 


#all: reading sending sniffer tx rx tx_fec
all: test_zfec tx_zfec rx_zfec

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)

reading: reading.o
	gcc -o $@ $^ $(LDFLAGS)

sending: sending.o
	gcc -o $@ $^ $(LDFLAGS)

../radiotap-library/radiotap.o: ../radiotap-library/radiotap.c
	gcc -c -o $@ $< $(CPPFLAGS)

../zfec/zfec/fec.o: ../zfec/zfec/fec.c
	gcc -c -o $@ $< $(CPPFLAGS)

sniffer: sniffer.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

rx: rx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o ../radiotap-library/radiotap.o
	gcc -o $@ $^ $(LDFLAGS)

#rx_fec: rx_fec.o ../radiotap-library/radiotap.o ../EZ-WifiBroadcast/wifibroadcast/fec.o
#rx_fec: rx_fec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
#	gcc -o $@ $^ $(LDFLAGS)

rx_zfec: rx_zfec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx_zfec: tx_zfec.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

test_zfec: test_zfec.o ../zfec/zfec/fec.o
	gcc -o $@ $^ $(LDFLAGS)

clean:
	rm -f reading sending sniffer rx tx rx_fec rx_zfec tx_zfec test_z:fec *~ *.o ../radiotap-library/radiotap.o ../zfec/zfec/fec.o
#	rm -f reading sending sniffer *.o
