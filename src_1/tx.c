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

  mon_interface_t interface;
  init(argv[1],&interface);

  uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
  size_t packet_header_length = 0;
  packet_header_length = packet_header_init(packet_transmit_buffer);

  int param_packet_length = 1450;
  int param_min_packet_length = 0;

  for(;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);

    select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
    if (FD_ISSET(STDIN_FILENO, &rfds)) {

      int in = read(STDIN_FILENO, packet_transmit_buffer + packet_header_length, param_packet_length);
      int plen = sizeof(wifi_packet_header_t) + packet_header_length + param_packet_length;

      int r = pcap_inject(interface.ppcap, packet_transmit_buffer, plen);
      if (r != plen) {
        pcap_perror(interface.ppcap, "Trouble injecting packet");
        exit(1);
      }
    }
  }
}
