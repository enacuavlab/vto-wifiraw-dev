#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>

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
} out_packet_buffer_t;  // packets with variable data len


typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t; // no padding between fields. 


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem


/*****************************************************************************/
int param_data_packets_per_block = 8;
int param_packet_length = 1450;
int param_min_packet_length = 0;


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
  wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_length);
  uint8_t *wifi_packet_data = packet_transmit_buffer + packet_header_length + sizeof(wifi_packet_header_t);
  uint8_t plen = param_packet_length + packet_header_length + sizeof(wifi_packet_header_t);

  out_packet_buffer_t pkts_out[param_data_packets_per_block]; // one block with several packets
  for (int i=0;i<param_data_packets_per_block;i++) {
    pkts_out[i].data=malloc(MAX_PACKET_LENGTH);
    pkts_out[i].len=0;
  }

  int blk=0;

  int inl,r;
  int pcnt=0, curr_pb=0, seq_nr=0;
  for(;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);

    select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
    if (FD_ISSET(STDIN_FILENO, &rfds)) {

      out_packet_buffer_t *pb = &pkts_out[curr_pb];
      if(pb->len == 0) pb->len += sizeof(payload_header_t); // first use of this packet, make room for header containing variable payload data length 

      inl=read(STDIN_FILENO, pb->data + pb->len, param_packet_length - pb->len);
      if(inl < 0 || inl > param_packet_length-pb->len) exit(-1);
      if(inl == 0) { usleep(1e5); continue; }

      pb->len += inl;
      if(pb->len >= param_min_packet_length) {

        payload_header_t *ph = (payload_header_t*)pb->data;
	ph->data_length = pb->len - sizeof(payload_header_t); // set variable payload data lengh in payload header
	pcnt++;

	if (curr_pb == param_data_packets_per_block-1) {      // reaching the last packet, we start injection sequence
	  for(int i=0;i<param_data_packets_per_block;i++) {
            wph->sequence_number = seq_nr;                              // set sequence number in wifi packet header
//            memcpy(wifi_packet_data, pkts_out[i].data, pkts_out[i].len);        // copy variable payload data
            memcpy(wifi_packet_data, pkts_out[i].data, param_packet_length);        // copy variable payload data
            r = pcap_inject(ppcap, packet_transmit_buffer, plen);
            if (r != plen) pcap_perror(ppcap, "Trouble injecting packet");

	    printf("blk %d pkt %d len %d\n",blk,i,param_packet_length);
	    seq_nr++;
	    pkts_out[i].len=0;
	  }
	  curr_pb=0;
	  blk++;
        } else curr_pb++;
      }
    }
    if(pcnt % 128 == 0) printf("%d data packets sent\n", pcnt);
  }
}
