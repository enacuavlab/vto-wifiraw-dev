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

  bool  crc_data[fec_n],crc_all,crc_second_half;

  pkt_t pkts_data[fec_n];
  for (int i=0;i<fec_n;i++) {pkts_data[i].data=malloc(PKT_SIZE); pkts_data[i].len=0;}
 
  uint8_t *fec_frame[fec_k];
  uint8_t fec_frame_data[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) fec_frame[i] = fec_frame_data[i];

  uint8_t *dec_in[fec_k];

  uint8_t *dec_out[fec_n - fec_k];
  uint8_t dec_outdata[fec_n - fec_k][PKT_DATA];
  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  unsigned indexes[fec_k];
  fec_t  *fec_p = fec_new(fec_k,fec_n);

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
      crc = (prd.m_nRadiotapFlags & 0x40) == 1; 
      if(crc) rx_status.wrong_crc_cnt++;
      rx_status.received_packet_cnt++;

      rx_p0 += sizeof(wifi_packet_header_t);
      uint32_t len = (((payload_header_t*)rx_p0)->data_length);
      int32_t temp = (len << 13); // fec packets have data_length signed bit set

      rx_p0 += sizeof(payload_header_t);

      if (fec_k > 0) {  // finding bloc containing arranged DATA and FEC frames
        bool reset=false;
        if (temp > 0) {     // data frame candidate
          if (di < fec_n) {
  	    if (di >= fi) { 
  	      memcpy(pkts_data[di].data,rx_p0,len);pkts_data[di].len=len;crc_data[di]=crc;di++;
  	    } else reset=true;
  	  } else reset=true;
        } else {           // fec candidate
          if (fi < fec_k) {
            if (di > 0) {  // at least one data frame before fec data
	      len = -len;
  	      memcpy((void *)fec_frame[fi],rx_p0,len);
	      fi++;
  	    } else reset=true;
  	  } else reset=true;
        }
        if (reset) {di = 0; fi = 0;}
        if ((di == fec_n) && (fi == fec_k)) { // the block is complete

// PATCH TEST
          crc_data[0] = 1; crc_data[1] = 1; crc_data[2] = 1; crc_data[3] = 1; // test recovery  !!!!

          crc_all = 0; crc_second_half = 0;
	  for (int i=0;i<fec_n;i++) {
	    crc_all = crc_all && crc_data[i]; 
	    if (i>=(fec_n-fec_k)) crc_second_half = crc_second_half && crc_data[i];
	  }

	  printf("%d %d\n",crc_all,crc_second_half);

	  if (!crc_second_half) {  
	    if (crc_all) {                       // only first half pkts can be recovered
              for(int i=0; i < fec_k; i++)   {
                if(crc_data[i]) {dec_in[i] = fec_frame[i];indexes[i] = i+fec_k;}
                else {  dec_in[i] = pkts_data[i].data; indexes[i] = i;}
                }
              }
              fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);

	      printf("fec_decode\n");

	      uint8_t error_pos = 0;             // rebuild output
              for (int i=0;i<fec_k;i++) {
                if (crc_data[i]) { memcpy(pkts_data[i].data,dec_out[error_pos],PKT_DATA); error_pos++; }
                else { memcpy(pkts_data[i].data,dec_in[i],PKT_DATA);}
	      }
            }

            for (int i=0;i<fec_n;i++) {
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
