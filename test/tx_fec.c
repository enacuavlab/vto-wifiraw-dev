#include <sys/time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>

#include "fec.h"


/*****************************************************************************/
/*
[ radiotap header  ]
[ ieee80211 header ]
[ payload 
    [ payload_header_t ]
]

*/

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
  pcap_t *ppcap;
} mon_interface_t;


typedef struct {
  int valid;
  int crc_correct;
  size_t len; 
  uint8_t *data;
} packet_buffer_t;


typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;


typedef struct {
    uint8_t packet_type;
    uint64_t data_nonce;  // big endian, data_nonce = (block_idx << 8) + fragment_idx
}  __attribute__ ((packed)) wblock_hdr_t;


/*****************************************************************************/
#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1450
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32

#define MAX_PACKET_SIZE 1510
#define MAX_FEC_PAYLOAD (MAX_PACKET_SIZE - sizeof(uint8_taRadiotapHeader) - sizeof(uint8_taRadiotapHeader) - sizeof(wblock_hdr_t))


/*****************************************************************************/
int packet_header_init(uint8_t *packet_header) {

  uint8_t *puint8_t = packet_header;

  uint8_taRadiotapHeader[8]=0x48; /* data rate : 36Mb/s */
  memcpy(packet_header, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
  puint8_t += sizeof(uint8_taRadiotapHeader);

  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) */
  memcpy(puint8_t, uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));
  puint8_t += sizeof (uint8_taIeeeHeader_data);

  return puint8_t - packet_header;
}


/*****************************************************************************/
void init(char *name,mon_interface_t *interface) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';

  interface->ppcap = pcap_open_live(name, 100, 0, 20, szErrbuf);
  if (interface->ppcap == NULL) {
    fprintf(stderr, "Unable to open interface %s in pcap: %s\n", name, szErrbuf);
  }

  if(pcap_setnonblock(interface->ppcap, 0, szErrbuf) < 0) {
    fprintf(stderr, "Error setting %s to blocking mode: %s\n", name, szErrbuf);
  }
}


/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  mon_interface_t interface;
  init(argv[1],&interface);


  uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
  size_t packet_header_length = 0;
  packet_header_length = packet_header_init(packet_transmit_buffer); // set headers in packet_transmit_buffer

  int param_packet_length = 1450;
  int param_min_packet_length = 0;

  int param_data_packets_per_block = 8;
  int param_fec_packets_per_block = 4; 

  int i;
  fec_t* fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block); 
  int sz=MAX_USER_PACKET_LENGTH;
  const unsigned char *blocks[param_data_packets_per_block];
  for (i=0;i<param_data_packets_per_block;i++) blocks[i]=malloc(sz);
  unsigned char *outblocks[param_fec_packets_per_block];
  for (i=0;i<param_fec_packets_per_block;i++) outblocks[i]=malloc(sz);
  int num=2;
  unsigned block_nums[] = {4, 7};
  

  packet_buffer_t pkts[param_data_packets_per_block]; // one block with several packets
  for (i=0;i<param_data_packets_per_block;i++) {
    packet_buffer_t *pkt = &pkts[i];
    memset(pkt,0,sizeof(packet_buffer_t));
    pkt->data = malloc(MAX_PACKET_LENGTH);
  }

  int inl,r;
  int plen;
  int pcnt = 0;
  int curr_pb = 0;
  int seq_nr=0;

  for(;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);

    select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
    if (FD_ISSET(STDIN_FILENO, &rfds)) {

      packet_buffer_t *pb = &pkts[curr_pb];
      if(pb->len == 0) pb->len += sizeof(payload_header_t);

      inl=read(STDIN_FILENO, pb->data + pb->len, param_packet_length - pb->len);
      if(inl < 0 || inl > param_packet_length-pb->len) exit(-1);
      if(inl == 0) {
        usleep(1e5);
        continue;
      }

      pb->len += inl;

      if(pb->len >= param_min_packet_length) {

        payload_header_t *ph = (payload_header_t*)pb->data;
	ph->data_length = pb->len - sizeof(payload_header_t); // set variable payload size in payload header
	pcnt++;

	if (curr_pb == param_data_packets_per_block-1) { // transmit block

          if (param_fec_packets_per_block) {
            for(i=0; i<param_data_packets_per_block; ++i) blocks[i] = pkts[i].data;
	    fec_encode(fec_p, blocks, outblocks, block_nums, num, sz);
          }		  

	  uint8_t *ptr=NULL;
	  bool interl = true;
	  int di = 0,fi = 0; // send data and FEC packets interleaved
          while ((di < param_data_packets_per_block) && (fi < param_fec_packets_per_block)) {

            if (di < param_data_packets_per_block) {
	      if (((fi < param_fec_packets_per_block) && (interl)) || (fi == param_fec_packets_per_block)) { 
	        ptr = pkts[di].data;
	        pkts[di].len=0;
	        di++;
	      }
	    }

            if (fi < param_fec_packets_per_block) {
	      if (((di < param_data_packets_per_block) && (!interl)) || (di == param_data_packets_per_block)) { 
                ptr = outblocks[fi];
	        fi++;
	      }
	    }

            memcpy(packet_transmit_buffer + packet_header_length + sizeof(wifi_packet_header_t), ptr, param_packet_length);
            wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_length);
            wph->sequence_number = seq_nr;
            plen = param_packet_length + packet_header_length + sizeof(wifi_packet_header_t);
            r = pcap_inject(interface.ppcap, packet_transmit_buffer, plen);
            if (r != plen) pcap_perror(interface.ppcap, "Trouble injecting packet");
	    seq_nr++;

	    interl = !interl; // toggle
	  }

	  curr_pb=0;
        } else curr_pb++;
      }

    }
    if(pcnt % 128 == 0) printf("%d data packets sent\n", pcnt);
  }
}
