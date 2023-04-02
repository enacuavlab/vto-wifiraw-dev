#include "wfb.h"

typedef struct {
  uint32_t len;
  uint8_t *pdat;
} pkt_t;

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint16_t headerSize = sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);


  uint32_t ret;
  uint8_t di;
  uint32_t inl = 0;

  fd_set rfds;
  struct timeval timeout;

  uint8_t portId = 5;

  uint8_t *pu8;
  uint8_t cpt=0;
  pkt_t pkt[fec_d];
  uint8_t buf[fec_d][PKT_SIZE];
  for (uint8_t i=0;i<fec_d;i++) {
    pkt[i].len = 0;
    pkt[i].pdat = (uint8_t *)(&buf[i]);
    pu8 = buf[i];
    memcpy(pu8, radiotap_hdr, sizeof(radiotap_hdr));
    pu8[2] = (sizeof(radiotap_hdr));
    pu8 += sizeof(radiotap_hdr);
    memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
    pu8[5] = portId;
    pu8 += sizeof(wifi_hdr);
    memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  }


  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {

      if (pkt[cpt].len == 0) pu8 = pkt[cpt].pdat + headerSize;

      inl = read(STDIN_FILENO, pu8 + pkt[cpt].len, PKT_DATA - pkt[cpt].len); // fill pkts with read input
      if (inl < 0) continue;
							   
      pkt[cpt].len += inl;
      if (pkt[cpt].len == PKT_DATA) cpt++;
      if (cpt == fec_d) ret=0;
    }
    if (ret == 0) {
      if (pkt[0].len > 0) {
	di = 0;
        while (di < fec_d) {
          pu8 = pkt[di].pdat + headerSize;
          memcpy(pu8, &(pkt[di].len), sizeof(uint32_t)); // copy variable payload length before payload data
          ret = pcap_inject(ppcap, buf[di], PKT_SIZE);
	  pkt[di].len = 0;
	  di++;
	}
      }
      cpt=0;
    }
  }
}
