#include "wfb.h"

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
  uint32_t len_d[fec_d];
  uint8_t buf_d[fec_d][PKT_SIZE];
  for (uint8_t i=0;i<fec_d;i++) {
    len_d[i] = 0;
    pu8 = buf_d[i];
    memcpy(pu8, radiotap_hdr, sizeof(radiotap_hdr));
    pu8[2] = (sizeof(radiotap_hdr));
    pu8 += sizeof(radiotap_hdr);
    memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
    pu8[5] = portId;
    pu8 += sizeof(wifi_hdr);
    memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  }

/*
  uint8_t *enc_in[fec_d]; // pointers to read packets in pkts_data
  uint8_t *enc_out[fec_k]; // pointers to encode packets in pkts_fec
  for (int i=0;i<fec_k;i++) enc_out[i] = pkt_k[cpt_d].pdat + headerSize0; 
  unsigned block_nums[fec_d];
  for (int i=0;i<fec_d;i++) block_nums[i] = i+fec_k;
  fec_t* fec_p = fec_new(fec_k,fec_n);
*/
/*
  uint8_t di,ki,li;
  uint16_t ret;
  uint32_t inl,offset;
  fd_set rfds;
  struct timeval timeout;
  bool usefec, interl;
*/

  uint8_t di,ki,li;
  uint16_t offset,ret;
  uint32_t inl = 0;
  fd_set rfds;
  struct timeval timeout;

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout);
    if (ret > 0) {            // headerSize1 = headerSize0 + sizeof(uint32_t)
      if (len_d[cpt_d] == 0) offset = headerSize1;
      inl = read(STDIN_FILENO, &(buf_d[cpt_d][offset]), PKT_DATA - len_d[cpt_d] );   // fill pkts with read input
      if (inl < 0) continue;
      len_d[cpt_d] += inl;
      offset += inl;
      if (len_d[cpt_d] == PKT_DATA) cpt_d++;
      if (cpt_d == fec_d) ret=0;
    }
    if (ret == 0) {
      if (len_d[0] > 0) {
	di = 0;
	while (di < fec_d) { // headerSize0 = sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr)
          memcpy(&(buf_d[di][headerSize0]), &len_d[di], sizeof(uint32_t)); // copy variable payload length before payload data
          ret = pcap_inject(ppcap, buf_d[di], PKT_SIZE);
          len_d[di] = 0;
	  di++;
	}
	cpt_d = 0;
      }
    }
  }
}

/*
      if (pkt_d[cpt_d].len == 0) { pu8 = pkt_d[cpt_d].pdat + headerSize1; enc_in[cpt_d] = pkt_d[cpt_d].pdat + headerSize0; }
      inl = read(STDIN_FILENO, pu8 + pkt_d[cpt_d].len, PKT_DATA - pkt_d[cpt_d].len); // fill pkts with read input
      if (inl < 0) continue;
      pkt_d[cpt_d].len += inl;
      if (pkt_d[cpt_d].len == PKT_DATA) cpt_d++;
      if (cpt_d == fec_d) ret=0;
    }
    if (ret == 0) {
      if (pkt_d[0].len > 0) {
	if (cpt_d < fec_d) usefec = false;
	else usefec = true;
        if (usefec) fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, fec_d, PKT_DATA);

	di=0;ki=0;li=0;interl = true;
        while ((usefec && ((di < fec_d) || (ki < fec_k)))
          || (!usefec && (li < fec_d))) {                         // send data and fec interleaved, when needed
	  if (usefec) {	
	    if ((di < fec_d)&&(interl)) { pu8 = pkt_d[di].pdat ; len = pkt_d[di].len ; pkt_d[di].len = 0; di ++; if(ki<fec_k) interl = !interl; }
	    else {
              if (ki < fec_k) { pu8 = pkt_k[ki].pdat ; len = pkt_k[ki].len ; ki ++; if(di<fec_d) interl = !interl; }
	    }
	  } else {  pu8 = pkt_d[li].pdat ; len = pkt_d[li].len ; pkt_d[li].len = 0;  li ++; }
          memcpy(pu8 + headerSize0, &len, sizeof(uint32_t)); // copy variable payload length before payload data
	
	  printf("(%d)(%d)(%d)\n",di,ki,len);
          ret = pcap_inject(ppcap, pu8, PKT_SIZE);
	}
        cpt_d=0;
      }
*/
