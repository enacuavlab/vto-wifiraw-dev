#include "wfb.h"
#include "radiotap_iter.h"

/*****************************************************************************/
typedef struct {
  uint32_t received_packet_cnt;
  uint32_t wrong_crc_cnt;
  int8_t current_signal_dbm;
} wifi_adapter_rx_status_t;

typedef struct  {
  int m_nChannel;
  int m_nChannelFlags;
  int m_nRate;
  int m_nAntenna;
  int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE]; szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 1600, 0, -1, szErrbuf);
  if (ppcap == NULL) exit(-1);
  if(pcap_setnonblock(ppcap, 1, szErrbuf) < 0) exit(-1);
  char szProgram[512];
  int port = 0; /* 0-255 */
  int nLinkEncap = pcap_datalink(ppcap);
  int n80211HeaderLength;
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
    n80211HeaderLength = 0x18;
    sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber
  } else exit(-1);
  struct bpf_program bpfprogram;
  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) exit(-1);
  int fd = pcap_get_selectable_fd(ppcap);

  uint8_t rx_buff[PKT_SIZE];
  uint8_t *rx_p0 = rx_buff; 
  struct pcap_pkthdr * ppcapPacketHeader = NULL;

  wifi_adapter_rx_status_t rx_status;
  memset(&rx_status,0,sizeof(rx_status));
  fd_set readset;int ret, u16HeaderLen, n;bool crc;
  PENUMBRA_RADIOTAP_DATA prd;

  bool  crc_data[param_data_packets_per_block];
  pkt_t pkts_data[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) {pkts_data[i].data=malloc(PKT_DATA);pkts_data[i].len=0;}
  pkt_t pkts_fec[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) {pkts_fec[i].data=malloc(PKT_DATA);pkts_fec[i].len=0;}

  const unsigned char *inpkts[param_fec_packets_per_block];
  unsigned char *outpkts[param_data_packets_per_block - param_fec_packets_per_block];
  unsigned indexes[param_fec_packets_per_block];
  fec_t  *fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);

  int di = 0,fi = 0;
  for(;;) {
    FD_ZERO(&readset);FD_SET(fd, &readset);
    ret = select(fd+1, &readset, NULL, NULL, NULL);
    if(ret == 0) break;
    if(FD_ISSET(fd, &readset)) {
      ret = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&rx_p0);
      if (ret < 0) exit(-1);
      if (ret != 1) continue;
      u16HeaderLen = (rx_p0[2] + (rx_p0[3] << 8));
      if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength)) continue;
      int bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
      if (bytes < 0) continue;
      struct ieee80211_radiotap_iterator rti;
      if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)rx_p0,ppcapPacketHeader->len,NULL)<0)continue;
      PENUMBRA_RADIOTAP_DATA prd;
      while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
        switch (rti.this_arg_index) {
          case IEEE80211_RADIOTAP_FLAGS:
            prd.m_nRadiotapFlags = *rti.this_arg;
            break;
          case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rx_status.current_signal_dbm = (int8_t)(*rti.this_arg);
            break;
        }
      }
      rx_p0 += u16HeaderLen + n80211HeaderLength;
      crc = (prd.m_nRadiotapFlags & 0x40) == 0;
      if(!crc) rx_status.wrong_crc_cnt++;
      rx_status.received_packet_cnt++;

//      printf("(%d)\n",((wifi_packet_header_t *)rx_p0)->sequence_number);

      rx_p0 += sizeof(wifi_packet_header_t);
      uint32_t len = (((payload_header_t*)rx_p0)->data_length);
      int32_t temp = (len << 13); // fec packets have data_length signed bit set

      rx_p0 += sizeof(payload_header_t);

      if (param_fec_packets_per_block > 0) {  // finding bloc containing arranged DATA and FEC frames
        bool reset=false;
        if (temp > 0) {     // data frame candidate
          if (di < param_data_packets_per_block) {
  	    if (di >= fi) { 
  	      memcpy(pkts_data[di].data,rx_p0,len);pkts_data[di].len=len;crc_data[di]=crc;di++;
  	    } else reset=true;
  	  } else reset=true;
        } else {           // fec candidate
          if (fi < param_fec_packets_per_block) {
            if (di > 0) {  // at least one data frame before fec data
	      len = -len;
  	      memcpy(inpkts,rx_p0,len);
	      pkts_fec[fi].len=len;fi++;
  	    } else reset=true;
  	  } else reset=true;
        }
        if (reset) {di = 0; fi = 0;}
        if ((di == param_data_packets_per_block) && (fi == param_fec_packets_per_block)) {
	 
          // option A nothing to decode, outpkts unchanged
          unsigned indexesA[] = {0, 1, 2, 3}; // (index[row] == row)
          fec_decode(fec_p, inpkts, outpkts, indexesA, 8);

  	  for (int i=0;i<param_data_packets_per_block;i++) {
            write(STDOUT_FILENO, pkts_data[i].data,  pkts_data[i].len);
            fflush(stdout);
  	  }
	  di=0;fi=0;
	}
      } else {  // not using fec
         write(STDOUT_FILENO, rx_p0,  len);
         fflush(stdout);
      }
    }
  }
}
