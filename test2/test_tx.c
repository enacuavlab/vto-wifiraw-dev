#include <time.h>
#include "wfb.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char errbuf[PCAP_ERRBUF_SIZE];
  ppcap_set_immediate_modecap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);

  uint8_taRadiotapHeader[8]=0x48; /* (0x48 x 500 kbps) = data rate : 36Mb/s  */
  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) */
  int headerSize1 = sizeof(uint8_taRadiotapHeader) + sizeof (uint8_taIeeeHeader_data);
  int headerSize2 = headerSize1 + sizeof(wifi_packet_header_t);
  int headerSize3 = headerSize2 + sizeof(payload_header_t);

  uint8_t *pkt_p = malloc(PKT_SIZE); 
  memcpy(pkt_p, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
  memcpy(pkt_p + sizeof(uint8_taRadiotapHeader), uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));

  fd_set rfds;
  struct timeval timeout;

  int ret;
  int nb_seq=0;
  int inl = 0;

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {

      inl=read(STDIN_FILENO, pkt_p + headerSize3, PKT_DATA);   // fill pkts with read input
      if (inl < 0) continue;

      ((wifi_packet_header_t *)(pkt_p + headerSize1))->sequence_number = nb_seq;
      ((payload_header_t *)(pkt_p + headerSize2))->data_length = inl;
      ret = pcap_inject(ppcap, pkt_p, PKT_SIZE);

      printf("(%d)(%d)(%d)\n", nb_seq, ret,inl);fflush(stdout);

      nb_seq++;
    }
  }
}
