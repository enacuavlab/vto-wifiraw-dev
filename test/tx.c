#include <sys/time.h>
#include <sys/resource.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>


/*****************************************************************************/
#define MAX_PACKET_LENGTH 4192
#define MAX_USER_PACKET_LENGTH 1450
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32


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


  int i,r; 
  int param_data_packets_per_block = 8;
  packet_buffer_t pkts[param_data_packets_per_block]; // on block with several packets
  for (i=0;i<param_data_packets_per_block;i++) {
    packet_buffer_t *pkt = &pkts[i];
    memset(pkt,0,sizeof(packet_buffer_t));
    pkt->data = malloc(MAX_PACKET_LENGTH);
  }

//  int param_packet_length = 1024;
  int param_packet_length = 1450;
  int param_min_packet_length = 0;

  int inl;
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

	if (curr_pb == param_data_packets_per_block-1) {

	  for(i=0;i<param_data_packets_per_block;i++) {

            wifi_packet_header_t *wph = (wifi_packet_header_t*)(packet_transmit_buffer + packet_header_length);
            wph->sequence_number = seq_nr;

            memcpy(packet_transmit_buffer + packet_header_length + sizeof(wifi_packet_header_t), pkts[i].data, param_packet_length);
            plen = param_packet_length + packet_header_length + sizeof(wifi_packet_header_t);

            r = pcap_inject(interface.ppcap, packet_transmit_buffer, plen);
            if (r != plen) pcap_perror(interface.ppcap, "Trouble injecting packet");

	    seq_nr++;
	    pkts[i].len=0;
	  }
	  curr_pb=0;
        } else curr_pb++;
      }

    }
    if(pcnt % 128 == 0) printf("%d data packets sent\n", pcnt);
  }
}
