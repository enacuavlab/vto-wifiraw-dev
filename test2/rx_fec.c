#include "wfb.h"
#include "radiotap_iter.h"

/*****************************************************************************/
typedef struct {
  bool r_crc;
  size_t r_len;
  uint8_t *r_data;
} rx_pkt_t;

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
} __attribute__((packed)) radiotap_data_t;

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

  int crc = 0;
  uint8_t rx_buff_cpt = 0;
  uint8_t rx_buff[fec_n][PKT_SIZE];

  rx_pkt_t data_pkt[fec_d];
  rx_pkt_t fec_pkt[fec_k];

  uint8_t *dec_in[fec_k];

  bool fec_used[fec_d];

  uint8_t *dec_out[fec_d];
  uint8_t dec_outdata[fec_d][PKT_DATA];
  for (int i=0;i<fec_d;i++) {dec_out[i] = dec_outdata[i];memset(dec_outdata[i],0,PKT_DATA);}

  pkt_t *frame_out[fec_k];

  uint8_t fec_cpt=0;

  struct pcap_pkthdr * ppcapPacketHeader = NULL;

  wifi_adapter_rx_status_t rx_status;
  memset(&rx_status,0,sizeof(rx_status));

  fec_t  *fec_p = fec_new(fec_k,fec_n);

  unsigned indexes[fec_k];
  int di = 0,fi = 0;
  fd_set readset;int ret, u16HeaderLen, n;
  radiotap_data_t prd;

  for(;;) {
    FD_ZERO(&readset);FD_SET(fd, &readset);
    ret = select(fd+1, &readset, NULL, NULL, NULL);
    if(ret == 0) break;
    if(FD_ISSET(fd, &readset)) {
      uint8_t *rx_p0 = rx_buff[rx_buff_cpt];
      ret = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&rx_p0);
      if (ret < 0) exit(-1);
      if (ret != 1) continue;
      u16HeaderLen = (rx_p0[2] + (rx_p0[3] << 8));
      if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength)) continue;
      int bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
      if (bytes < 0) continue;
      struct ieee80211_radiotap_iterator rti;
      if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)rx_p0,ppcapPacketHeader->len,NULL)<0)continue;
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
      crc = ((prd.m_nRadiotapFlags & 0x40) == 0);
      if(crc) rx_status.wrong_crc_cnt++;
      rx_status.received_packet_cnt++;

      uint32_t seq_num = ((wifi_packet_header_t*)rx_p0)->sequence_number;

      rx_p0 += sizeof(wifi_packet_header_t);
      uint32_t len = (((payload_header_t*)rx_p0)->data_length);
      int32_t temp = (len << 13); // fec packets have data_length signed bit set

      rx_p0 += sizeof(payload_header_t);

      if (fec_k > 0) {  // finding bloc containing data and fec frames
        bool reset=false;
        if (temp > 0) {     // data frame candidate
          if (di < fec_d) {
  	    if (di >= fi) { 
  	      data_pkt[di].r_crc = crc;
	      data_pkt[di].r_len = len;
	      data_pkt[di].r_data = rx_p0;
	      di++;
  	    } else reset=true;
  	  } else reset=true;
        } else {           // fec candidate
          if (fi < fec_k) {
            if (di > 0) {  // at least one data frame before fec data
	      len = -len;
  	      fec_pkt[di].r_crc = crc;
  	      fec_pkt[di].r_len = len;
  	      fec_pkt[di].r_data = rx_p0;
	      fi++;
  	    } else reset=true;
  	  } else reset=true;
        }

        printf("(%d)(%d)(%d)(%d)\n",di,fi,reset,true);fflush(stdout);

        if (reset) {di = 0; fi = 0;}
        if (di == fec_d) {

          int map_cpt=0;
          for (int i=0;i<fec_d;i++) if (data_pkt[i].r_crc) map_cpt++;
	  if (map_cpt>0) {

            if (fi == fec_k) { // the block is complete

              fec_cpt=0;
              for (int i=0;i<fec_k;i++) if (fec_pkt[i].r_crc) fec_cpt++;
  	      if (map_cpt <= (fec_k - fec_cpt)) { // there are enought valid fec to recover faulty data

                // 1) set decoder options with dec_in and indexes
                // 2) preallocate frameout, with suitable pointers to valid and/or rebuild data
                //    (decode will produce in dec_out, only packet not present in dec_in)
                fec_cpt=0;
                memset(fec_used,0,sizeof(fec_used));
                for(int i=0; i < fec_k; i++)                 {
                  if(data_pkt[di].r_crc) {
                    for (int j=0; j < fec_d; j++) {
                      if ((!fec_pkt[j].r_crc)&&(!fec_used[j])) {
                        dec_in[i] = fec_pkt[j].r_data;
                        indexes[i] = j+fec_k;
                        fec_used[j]=1;
                        fec_cpt++;

                        frame_out[i]->data = dec_out[fec_cpt];
		        frame_out[i]->len =  fec_pkt[j].r_len; // why not !
                        break;
                      }
                    }
                  } else {
                    dec_in[i] = data_pkt[i].r_data;
                    indexes[i] = i;

                    frame_out[i]->data = data_pkt[i].r_data;
	            frame_out[i]->len = data_pkt[i].r_len;
                  }
                }

                fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);
                free(fec_p);

                for (int i=0;i<fec_n;i++) {
                  write(STDOUT_FILENO,frame_out[i]->data,frame_out[i]->len);
                  fflush(stdout);
                }
	      }
	      fi=0;
	    }
	  }
	  di=0;
	}
      } else {  // not using fec
         write(STDOUT_FILENO, rx_p0,  len);
         fflush(stdout);
      }
      rx_buff_cpt++;
    }
  }
}
