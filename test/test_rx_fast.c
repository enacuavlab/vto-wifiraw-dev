//#include "wfb.h"
#include <pcap.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>



typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;

typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;


/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  struct bpf_program bpfprogram;
  char szProgram[512];
  char szErrbuf[PCAP_ERRBUF_SIZE];

  szErrbuf[0] = '\0';

  pcap_t *ppcap = pcap_open_live(argv[1], 1600, 0, -1, szErrbuf);
  if(pcap_setnonblock(ppcap, 1, szErrbuf) < 0) exit(-1);
  int port = 5;
  int n80211HeaderLength = 0x18; // length of standard IEEE802.11 data frame header is 24 bytes = 0x18
  sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber

  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) exit(-1);
  pcap_freecode(&bpfprogram);
  int selectable_fd = pcap_get_selectable_fd(ppcap);

  struct pcap_pkthdr * ppcapPacketHeader = NULL;
  uint8_t payloadBuffer[4192];
  uint8_t *pu8Payload = payloadBuffer;
  int bytes, retval, num;
  size_t data_len;
  int u16HeaderLen;

  wifi_packet_header_t *wph;

  for(;;) {
    fd_set readset;
/*
    struct timeval to;
    to.tv_sec = 0;
    to.tv_usec = 1e5;
*/	

    FD_ZERO(&readset);
    FD_SET(selectable_fd, &readset);

//    int n = select(selectable_fd + 1, &readset, NULL, NULL, &to);
    int n = select(selectable_fd + 1, &readset, NULL, NULL, NULL);

//    if(n == 0) break;
    if(FD_ISSET(selectable_fd, &readset)) {

      printf("HELLO (%d)\n",n);

      retval = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&pu8Payload); 
      if (retval == 1) {
        u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));
	if (ppcapPacketHeader->len >= (u16HeaderLen + n80211HeaderLength)) {
	  bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
	  if (bytes > 0) {
	    pu8Payload += u16HeaderLen + n80211HeaderLength;
	    data_len = bytes;

            wph = (wifi_packet_header_t*)pu8Payload;
            pu8Payload += sizeof(wifi_packet_header_t);
            data_len -= sizeof(wifi_packet_header_t);

            num = wph->sequence_number;

            payload_header_t *ph = (payload_header_t*)pu8Payload;

            write(STDOUT_FILENO, pu8Payload + sizeof(payload_header_t), ph->data_length);
	  }
	}
      }
    }
  }
}
