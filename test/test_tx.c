#include "wfb.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

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
}
