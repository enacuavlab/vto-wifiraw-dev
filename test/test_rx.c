#include "wfb.h"
#include "radiotap_iter.h"

#define payload_head (sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr) + 7 ) // ?!
#define payload_data (payload_head + sizeof(uint32_t))

/*****************************************************************************/
typedef struct  {
  int m_nChannel;
  int m_nChannelFlags;
  int m_nRate;
  int m_nAntenna;
  int m_nRadiotapFlags;
} __attribute__((packed)) radiotap_data_t;
radiotap_data_t prd;

typedef struct {
  uint32_t rcv_pkt_cnt;
  uint32_t wrong_crc_cnt;
  int8_t signal_dbm;
} wifi_adapter_rx_status_t;
wifi_adapter_rx_status_t rx_status;

uint32_t n80211HeaderLength = sizeof(radiotap_hdr);

/*****************************************************************************/
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {

  // pkt = sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr) + DATA + 4 bytes crc 
  // DATA = sizeof(uint32_t) + ( paysize * sizeof(uint8_t) )
/*  
  uint32_t paysize;
  memcpy(&paysize, &pkt[payload_head], sizeof(paysize));
  printf("(%u)\n",paysize);

  write(STDOUT_FILENO, &pkt[payload_data], paysize);
*/
  uint32_t n,crc;
  const uint8_t *rx_p0 = pkt;
  uint32_t u16HeaderLen = (rx_p0[2] + (rx_p0[3] << 8));
  if (hdr->len >= (u16HeaderLen + n80211HeaderLength)) {
    int bytes = hdr->len - (u16HeaderLen + n80211HeaderLength);
    if (bytes >= 0) {
      struct ieee80211_radiotap_iterator rti;
      if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)rx_p0,hdr->len,NULL)>=0) {
        while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
          switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_FLAGS:
              prd.m_nRadiotapFlags = *rti.this_arg;
              break;
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
              rx_status.signal_dbm = (int8_t)(*rti.this_arg);
              break;
          }
        }
        rx_p0 += u16HeaderLen + n80211HeaderLength;
        int checksum_correct = ((prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_BADFCS) == 0);
        if(!checksum_correct) rx_status.wrong_crc_cnt++;
        rx_status.rcv_pkt_cnt++;
      
        printf("(%d)(%d)(%d)\n",bytes,rx_status.wrong_crc_cnt,rx_status.signal_dbm);
      }
    }
  }
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0)       exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0)         exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0)         exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0)  exit(-1);
  if (pcap_activate(ppcap) !=0)                exit(-1);
  if (pcap_setnonblock(ppcap, 1, errbuf) != 0) exit(-1);

  uint8_t port = 5;
  int nLinkEncap = pcap_datalink(ppcap);
  char szProgram[512];
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
    sprintf(szProgram, "ether[0x00:2] == 0x8800 && ether[0x04:2] == 0xff%.2x", port); // match on frametype and port
  } else exit(-1);

  struct bpf_program bpfprogram;
  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) exit(-1);
  pcap_freecode(&bpfprogram);

  memset(&rx_status,0,sizeof(rx_status));

  pcap_loop(ppcap, 0, captured_packet, NULL);
  return 0;
}
