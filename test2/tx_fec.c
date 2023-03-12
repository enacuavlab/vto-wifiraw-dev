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
#define MAX_PACKET_LENGTH 4192

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
} in_packet_buffer_t;  // packets with variable data len


typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t; // no padding between fields. 


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem


/*****************************************************************************/
int param_fec_packets_per_block = 4;
int param_data_packets_per_block = 8;
int param_packet_length = 1450;


/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);
  char szErrbuf[PCAP_ERRBUF_SIZE];szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 100, 0, 20, szErrbuf);
  if (ppcap == NULL) exit(-1);
  if(pcap_setnonblock(ppcap, 0, szErrbuf) < 0) exit(-1);
  uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
  uint8_t *packet_header = packet_transmit_buffer;
  uint8_t *puint8_t = packet_header;
  uint8_taRadiotapHeader[8]=0x48; /* data rate : 36Mb/s */
  memcpy(packet_header, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
  puint8_t += sizeof(uint8_taRadiotapHeader);
  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) */
  memcpy(puint8_t, uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));
  puint8_t += sizeof (uint8_taIeeeHeader_data);
  int packet_header_length =  puint8_t - packet_header;
  int plen = param_packet_length + packet_header_length + sizeof(wifi_packet_header_t);
  wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_length);
  in_packet_buffer_t pkts_in[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) {
    pkts_in[i].data=malloc(param_packet_length);pkts_in[i].len=0;
  }

  in_packet_buffer_t pkts_fec[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) {
    pkts_fec[i].data=malloc(param_packet_length);pkts_fec[i].len=0;
  }
  fec_t* fec_p;
  if (param_fec_packets_per_block) fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);
  const unsigned char *blocks[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) blocks[i]=malloc(param_packet_length);
  unsigned char *outblocks[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) outblocks[i]=malloc(param_packet_length);
  int num=2;
  unsigned block_nums[] = {4, 7};

  bool usefec;
  struct timeval timeout;
  fd_set rfds;
  int inl,ret;
  int curr_pb=0, seq_nr=0;
  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout);
    if (ret > 0) {
      in_packet_buffer_t *pb = &pkts_in[curr_pb];
      if(pb->len == 0) pb->len += sizeof(payload_header_t);                        // on first use, make room for payload header
      inl=read(STDIN_FILENO, pb->data + pb->len, param_packet_length - pb->len);   // fill pkts with inputs
      if (inl < 0) continue;
      pb->len += inl;
      if (pb->len == param_packet_length) curr_pb++;         // current packet is full, switch to next packet
      if (curr_pb == param_data_packets_per_block) ret = 0;  // all pkts are full, continue with send sequence below
    }
    if (ret == 0) { 
      if ((pkts_in[0].len) != 0) {                           // timeout with data available to send, or full pkts to send
        int nbpkts;
	if (curr_pb == param_data_packets_per_block) nbpkts = param_data_packets_per_block;
	else nbpkts = curr_pb+1;


        usefec = ((param_fec_packets_per_block) && (curr_pb == param_data_packets_per_block));  // use fec when all full packet are sent
        if (usefec) {
          for(int i=0; i<param_data_packets_per_block; ++i) blocks[i] = pkts_in[i].data;
          fec_encode(fec_p, blocks, outblocks, block_nums, num, param_packet_length);
          for(int i=0; i<param_fec_packets_per_block; ++i) {
	    memset(pkts_fec[i].data, 0, sizeof(payload_header_t));
	    memcpy(pkts_fec[i].data + sizeof(payload_header_t), &outblocks[i], param_packet_length - sizeof(payload_header_t));
	  }
        }

	printf("usefec=%d\n",usefec);fflush(stdout);
        uint8_t *ptr=NULL;
        bool interl = true;
        int di = 0,fi = 0, li=0;                                   // send data and fec interleaved
        while ((usefec && ((di < param_data_packets_per_block) || (fi < param_fec_packets_per_block)))
          || (!usefec && (li < nbpkts))) {
	  if (usefec) {	
            if (di < param_data_packets_per_block) {
              if (((fi < param_fec_packets_per_block) && (interl)) || (fi == param_fec_packets_per_block)) {
                  ptr = &(pkts_in[di].data); di++;
                }
              }
  	    if ((param_fec_packets_per_block) && (fi < param_fec_packets_per_block)) {
                if (((di < param_data_packets_per_block) && (!interl)) || (di == param_data_packets_per_block)) {
                  ptr = &pkts_fec[fi]; fi++;
                }
            }
	  } else {
             ptr = &(pkts_in[li].data); li++;
	  }
          interl = !interl; // toggle
	}

/*
        for (int i=0;i<nbpkts;i++) {
	  wph->sequence_number = seq_nr;                               // set sequence number in wifi packet header
          payload_header_t *ph = (payload_header_t*)pkts_in[i].data;   // set variable payload size in
          ph->data_length = pkts_in[i].len - sizeof(payload_header_t); // previous allocated payload header
          memcpy(packet_transmit_buffer + packet_header_length + sizeof(wifi_packet_header_t), pkts_in[i].data, param_packet_length);
	  ret = pcap_inject(ppcap, packet_transmit_buffer, plen);      // inject all transmit  buffer
	  seq_nr++;
	  pkts_in[i].len = 0;
  	}
	curr_pb = 0;
*/
      }
    }
  }
}
