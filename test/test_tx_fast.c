//#include "wfb.h"
#include <sys/resource.h>
#include <sys/time.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/select.h>
#include <unistd.h>

static uint8_t u8aRadiotapHeader[] = {
        0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
        0x00, // datarate (will be overwritten later in packet_header_init)
        0x00,
        0x00, 0x00
};

static uint8_t u8aIeeeHeader_data[] = {
        0x08, 0xbf, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00,// 1st byte of IEEE802.11 RA (mac) must be 0xff or something odd, otherwise strange things happen. second byte is the port (will be overwritten later)
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
        0x00, 0x00, // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};


/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  int port = 5;
  uint8_t packet_transmit_buffer[4192];
  uint8_t *pu8 = packet_transmit_buffer;
  u8aRadiotapHeader[8]=0x48;
  memcpy(pu8, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
  pu8 += sizeof(u8aRadiotapHeader);
  u8aIeeeHeader_data[5] = port;
  memcpy(pu8, u8aIeeeHeader_data, sizeof (u8aIeeeHeader_data));
  pu8 += sizeof (u8aIeeeHeader_data);

  size_t packet_header_len = pu8 - packet_transmit_buffer;

  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 100, 0, 20, szErrbuf);
  pcap_setnonblock(ppcap, 0, szErrbuf);

  typedef struct {
    uint32_t data_length;
  } __attribute__((packed)) payload_header_t;

  typedef struct {
    uint32_t sequence_number;
  } __attribute__((packed)) wifi_packet_header_t;

  uint8_t buf[4][1024];
  size_t  len[4];
  uint8_t cpt = 0;

  int di=0;

  int seq_nr;

  fd_set rdfs, fifo_set;
  int ret;

  FD_ZERO(&fifo_set);
  FD_SET(STDIN_FILENO, &fifo_set);

  while(true) {

    rdfs = fifo_set;

    ret = select(STDIN_FILENO + 1, &rdfs, NULL, NULL, NULL);
    if(ret < 0) {
      perror("select");
      return (1);
    }
    if(!FD_ISSET(STDIN_FILENO, &rdfs)) {
      continue;
    }

    if(len[cpt] == 0) {
      len[cpt] += sizeof(payload_header_t); //make space for a length field (will be filled later)
    }
    int inl = read(STDIN_FILENO, &(buf[cpt][len[cpt]]), 1024 - len[cpt]);
    if(inl < 0 || inl > 1024 - len[cpt]) {
      perror("reading stdin");
      return 1;
    }
    if(inl == 0) {
      fprintf(stderr, "Warning: Lost connection to stdin. Please make sure that a data source is connected\n");
      usleep(1e5);
      continue;
    }
    len[cpt] += inl;
    if (len[cpt] == 1024) {
      if (cpt < 4) cpt++;
      else {
	di = 0;
        while(di < 4) {
          wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_len);
          wph->sequence_number = seq_nr;
          memcpy(packet_transmit_buffer + packet_header_len + sizeof(wifi_packet_header_t), &(buf[di]), 1024);
      	  int plen = len[di] + packet_header_len + sizeof(wifi_packet_header_t);
          int r = pcap_inject(ppcap, packet_transmit_buffer, plen);
          di++;
        }
	seq_nr++;
        for(int i=0; i<4; i++) len[i] = 0;
        cpt = 0;
      }
    }
  }
}
