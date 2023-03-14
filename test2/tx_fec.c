#include <sys/time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <fcntl.h>
#include "fec.h"

/*****************************************************************************/
static uint8_t uint8_taRadiotapHeader[] = {
  0x00, 0x00, // <-- radiotap version
  0x0c, 0x00, // <- radiotap header length
  0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
  0x00, // datarate (will be overwritten later)
  0x00,
  0x00, 0x00
};

static uint8_t uint8_taIeeeHeader_data[] = {
  0x08, 0xbf, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
  0xff, 0x00, 0x00, 0x00, 0x00, 0x00,// 1st byte of IEEE802.11 RA (mac) must be 0xff or something odd, otherwise strange things happen. second byte is the port (will be overwritten later)
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
  0x00, 0x00, // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};

/*****************************************************************************/
typedef struct {
  size_t len; 
  uint8_t *data;
} pkt_t;  // packets with variable data len


typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t; // no padding between fields. 


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem


/*****************************************************************************/
//int param_fec_packets_per_block = 0; // NO FEC
int param_fec_packets_per_block = 4;
int param_data_packets_per_block = 8;

#define PKT_SIZE 1510
#define PKT_PAYL (PKT_SIZE - sizeof(uint8_taRadiotapHeader) - sizeof(uint8_taIeeeHeader_data) - sizeof(wifi_packet_header_t)) 
#define PKT_DATA (PKT_PAYL - sizeof(pkt_t))

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE];szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 100, 0, 20, szErrbuf);
  if (ppcap == NULL) exit(-1);
  if(pcap_setnonblock(ppcap, 0, szErrbuf) < 0) exit(-1);

  uint8_t tx_buff[PKT_SIZE];
  uint8_taRadiotapHeader[8]=0x48; /* data rate : 36Mb/s */
  memcpy(tx_buff, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) */
  memcpy(tx_buff + sizeof(uint8_taRadiotapHeader), uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));
  uint8_t *tx_p0 = tx_buff + sizeof(uint8_taRadiotapHeader) + sizeof (uint8_taIeeeHeader_data);
  uint8_t *tx_p1 = tx_p0 + sizeof(wifi_packet_header_t); 
  uint8_t *tx_p2 = tx_p1 + sizeof(payload_header_t);

  pkt_t pkts_data[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) {pkts_data[i].data=malloc(PKT_DATA);pkts_data[i].len=0;}

  pkt_t pkts_fec[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) {pkts_fec[i].data=malloc(PKT_DATA);pkts_fec[i].len=0;}

  fec_t* fec_p;
  if (param_fec_packets_per_block) fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);
  const unsigned char *blocks[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) blocks[i]=malloc(PKT_DATA);
  unsigned char *outblocks[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) outblocks[i]=malloc(PKT_DATA);

  unsigned block_nums[] = {4, 5, 6, 7};
  int num=(param_data_packets_per_block - param_fec_packets_per_block);

  fd_set rfds;struct timeval timeout;bool usefec;pkt_t *pkt_p;int inl, ret, nb_pkts;int nb_curr=0, nb_seq=0;
  bool interl = true;int di = 0,fi = 0, li=0;  
  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout);
    if (ret > 0) {
      pkt_p = &pkts_data[nb_curr];
      if(pkt_p->len == 0) pkt_p->len += sizeof(payload_header_t);                   // on first use, make room for payload header
      inl=read(STDIN_FILENO, pkt_p->data + pkt_p->len, PKT_DATA - pkt_p->len);   // fill pkts with inputs
      if (inl < 0) continue;
      pkt_p->len += inl;
      if (pkt_p->len == PKT_DATA) nb_curr++;                         // current packet is full, switch to next packet
      if (nb_curr == param_data_packets_per_block) ret = 0;          // all pkts are full, continue with send sequence below
    }
    if (ret == 0) { 
      if ((pkts_data[0].len) != 0) {                                 // timeout with data available to send, or full pkts to send
	if (nb_curr == param_data_packets_per_block) nb_pkts = param_data_packets_per_block;
	else nb_pkts = nb_curr+1;
	usefec = false;                                              // use fec when all full packet are sent
        if ((param_fec_packets_per_block) && (nb_curr == param_data_packets_per_block)) usefec=true; 
        if (usefec) {
          for(int i=0; i<param_data_packets_per_block; ++i) memcpy((void *)blocks[i],pkts_data[i].data,PKT_DATA);
          fec_encode(fec_p, blocks, outblocks,  block_nums, num, PKT_DATA);
          for(int i=0; i<param_fec_packets_per_block; ++i) {
            pkts_fec[i].len = (-PKT_DATA);                          // set unsigned data_length signed bit for fec
	    memcpy(pkts_fec[i].data,outblocks, PKT_DATA);
	  }
        }
	di=0;fi=0;li=0;
        while ((usefec && ((di < param_data_packets_per_block) || (fi < param_fec_packets_per_block)))
          || (!usefec && (li < nb_pkts))) {                         // send data and fec interleaved, when needed
	  if (usefec) {	
            if (di < param_data_packets_per_block) {
              if (((fi < param_fec_packets_per_block) && (interl)) || (fi == param_fec_packets_per_block)) {
                  pkt_p = &pkts_data[di]; di ++;
                }
              }
  	    if ((param_fec_packets_per_block) && (fi < param_fec_packets_per_block)) {
                if (((di < param_data_packets_per_block) && (!interl)) || (di == param_data_packets_per_block)) {
                  pkt_p = &pkts_fec[fi]; fi ++;
                }
            }
	  } else {
              pkt_p = &pkts_data[li]; li ++;
	  }
          interl = !interl; // toggle
          ((wifi_packet_header_t *)tx_p0)->sequence_number = nb_seq;
	  ((payload_header_t *) tx_p1)->data_length = pkt_p->len;
          memcpy(tx_p2, (void *)pkt_p, PKT_PAYL);
	  ret = pcap_inject(ppcap, tx_buff, PKT_SIZE);
	  printf("%d %d\n",nb_seq,ret);
	  pkt_p->len = 0; 
	  nb_seq++;
	}
	nb_curr = 0;
      }
    }
  }
}
