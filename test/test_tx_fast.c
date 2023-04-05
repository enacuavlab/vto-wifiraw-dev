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

#define MAX_PACKET_LENGTH 4192

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  int port = 5;
  uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
  uint8_t *pu8 = packet_transmit_buffer;
  u8aRadiotapHeader[8]=0x48;
  memcpy(pu8, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
  pu8 += sizeof(u8aRadiotapHeader);
  u8aIeeeHeader_data[5] = port;
  memcpy(pu8, u8aIeeeHeader_data, sizeof (u8aIeeeHeader_data));
  pu8 += sizeof (u8aIeeeHeader_data);

  size_t packet_header_len = pu8 - packet_transmit_buffer;

/*
  uint8_t buf[PKT_SIZE];
  uint8_t *pu8 = buf;

  memcpy(buf, radiotap_hdr, sizeof(radiotap_hdr));
  buf[2] = (sizeof(radiotap_hdr));

  pu8 += sizeof(radiotap_hdr);

  memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
  uint8_t portId = 5;
  pu8[5] = portId;

  pu8 += sizeof(wifi_hdr);

  memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  pu8 += sizeof(llc_hdr);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);
*/

  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 100, 0, 20, szErrbuf);
  pcap_setnonblock(ppcap, 0, szErrbuf);

/*  
  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);

  uint8_t *pu8_payload_head = pu8;
  pu8 += sizeof(pay_hdr_t);

  uint16_t inl, ret, seq_blk_nb = 0;

  fd_set rfds;
  struct timeval timeout;
*/

  typedef struct {
    uint32_t data_length;
  } __attribute__((packed)) payload_header_t;

  typedef struct {
    uint32_t sequence_number;
  } __attribute__((packed)) wifi_packet_header_t;

  typedef struct {
    size_t len; 
    uint8_t *data;
  } packet_buffer_t;

  typedef struct {
    int curr_pb;
    packet_buffer_t *pbl;
  } fifo_t;

  fifo_t fifo;

  int pcnt = 0;
  fd_set fifo_set;
  int max_fifo_fd = -1;
  int seq_nr;

  FD_ZERO(&fifo_set);
  FD_SET(STDIN_FILENO, &fifo_set);
  while(true) {
    fd_set rdfs;
    int ret;
    rdfs = fifo_set;
    ret = select(STDIN_FILENO + 1, &rdfs, NULL, NULL, NULL);
    if(ret < 0) {
      perror("select");
      return (1);
    }
    if(!FD_ISSET(STDIN_FILENO, &rdfs)) {
      continue;
    }
    packet_buffer_t *pb = fifo.pbl + fifo.curr_pb;
    if(pb->len == 0) {
      pb->len += sizeof(payload_header_t); //make space for a length field (will be filled later)
    }
    int inl = read(STDIN_FILENO, pb->data + pb->len, 1024 - pb->len);
    if(inl < 0 || inl > 1024-pb->len) {
      perror("reading stdin");
      return 1;
    }
    if(inl == 0) {
      fprintf(stderr, "Warning: Lost connection to stdin. Please make sure that a data source is connected\n");
      usleep(1e5);
      continue;
    }
    pb->len += inl;
    if(pb->len >= 0) {
      payload_header_t *ph = (payload_header_t*)pb->data;
      ph->data_length = pb->len - sizeof(payload_header_t);
      pcnt++;
      if(fifo.curr_pb == 8-1) {

        while(di < data_packets_per_block || fi < fec_packets_per_block) {
          if(di < data_packets_per_block) {

            wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_len);
            wph->sequence_number = seq_nr;
            memcpy(packet_transmit_buffer + packet_header_len + sizeof(wifi_packet_header_t), packet_data, 1024);
            int plen = packet_length + packet_header_len + sizeof(wifi_packet_header_t);
            int r = pcap_inject(ppcap, packet_transmit_buffer, plen);

	  } 
	  seq_nr_tmp++;
          di++;
	}
        *seq_nr += data_packets_per_block + fec_packets_per_block;
        for(i=0; i< data_packets_per_block; ++i) pbl[i].len = 0;

	fifo.curr_pb = 0;
      } else  fifo.curr_pb++;
    }

    if(pcnt % 128 == 0) {
      printf("%d data packets sent\r", pcnt);
    }
  }
}



/*  
  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {

      inl=read(STDIN_FILENO, pu8, PKT_DATA);   // fill pkts with read input
      if (inl < 0) continue;

      (((pay_hdr_t *)pu8_payload_head)->seq_blk_nb) = seq_blk_nb;
      (((pay_hdr_t *)pu8_payload_head)->len) = inl;

      ret = pcap_inject(ppcap, buf, PKT_SIZE);
      seq_blk_nb++;
    }
  }
*/
