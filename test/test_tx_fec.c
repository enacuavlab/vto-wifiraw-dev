#include "wfb.h"

typedef struct {
  uint32_t len;
  uint8_t *pdat;
} pkt_t;

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint16_t headerSize0 = sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr);
  uint16_t headerSize1 = headerSize0 + sizeof(uint32_t);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);


  uint8_t *pu8;
  uint8_t portId = 5;

  uint8_t cpt_d=0;
  pkt_t pkt_d[fec_d];
  uint8_t buf_d[fec_d][PKT_SIZE];
  for (uint8_t i=0;i<fec_d;i++) {
    pkt_d[i].len = 0;
    pkt_d[i].pdat = (uint8_t *)(&buf_d[i]);
    pu8 = buf_d[i];
    memcpy(pu8, radiotap_hdr, sizeof(radiotap_hdr));
    pu8[2] = (sizeof(radiotap_hdr));
    pu8 += sizeof(radiotap_hdr);
    memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
    pu8[5] = portId;
    pu8 += sizeof(wifi_hdr);
    memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  }

  uint32_t ret;
  uint8_t di;
  uint32_t inl = 0;
  fd_set rfds;
  struct timeval timeout;

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {
      if (pkt_d[cpt_d].len == 0) pu8 = pkt_d[cpt_d].pdat + headerSize1;
      inl = read(STDIN_FILENO, pu8 + pkt_d[cpt_d].len, PKT_DATA - pkt_d[cpt_d].len); // fill pkts with read input
      if (inl < 0) continue;
      pkt_d[cpt_d].len += inl;
      if (pkt_d[cpt_d].len == PKT_DATA) cpt_d++;
      if (cpt_d == fec_d) ret=0;
    }
    if (ret == 0) {
      if (pkt_d[0].len > 0) {
	di = 0;
        while (di < fec_d) {
          pu8 = pkt_d[di].pdat + headerSize0;
          memcpy(pu8, &(pkt_d[di].len), sizeof(uint32_t)); // copy variable payload length before payload data
          ret = pcap_inject(ppcap, buf_d[di], PKT_SIZE);
	  pkt_d[di].len = 0;
	  di++;
	}
        cpt_d=0;
      }
    }
  }
}
