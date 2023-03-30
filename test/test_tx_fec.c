#include "wfb.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t buf[PKT_SIZE];
  uint8_t *pu8 = buf;

  uint8_t *pkts_fec[fec_k][fec_k][PKT_SIZE];
  for (int i=0;i<fec_k;i++) {
    pkts_fec[i]=*pkts_fec[i][];
    memcpy(&pkts_fec[i],radiotap_hdr, sizeof(radiotap_hdr));
    memcpy(&pkts_fec[i]+sizeof(radiotap_hdr),wifi_hdr, sizeof(wifi_hdr));
    memcpy(&pkts_fec[i]+sizeof(wifi_hdr),llc_hdr, sizeof(llc_hdr));
  }
 
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
  pu8 += sizeof(uint32_t);

  uint8_t ret;
  uint32_t inl = 0;

  fd_set rfds;
  struct timeval timeout;

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {
/*
      pkt_p = &pkts_data[nb_curr];
      if (pkt_p->len == 0) enc_in[nb_curr] = pkt_p->data + headerSize3;                        // set data block address 
      inl=read(STDIN_FILENO, pu8 + pkt_p->len, PKT_DATA - pkt_p->len);   // fill pkts with read input
      if (inl < 0) continue;
      pkt_p->len += inl;
      if (pkt_p->len == PKT_DATA) nb_curr++;  // current packet is full, switch to next packet
      if (nb_curr == fec_d) ret = 0;          // all pkts are full, continue with send sequence below
*/					     
    }
    if (ret == 0) {
      if ((pkts_data[0].len) > 0) {           // timeout with data available to send, or full pkts to send

        inl=read(STDIN_FILENO, pu8, PKT_DATA);   // fill pkts with read input
        if (inl < 0) continue;

        memcpy(pu8_payload_head,&inl,sizeof(inl)); // copy variable payload length before payload data

        ret = pcap_inject(ppcap, buf, PKT_SIZE);
      }
    }
  }
}
