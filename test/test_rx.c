#include "wfb.h"
#include "radiotap_iter.h"

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


uint32_t crc32_table[256];


/*****************************************************************************/
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {

  uint32_t n, crc;
  const uint8_t *rx_p0 = pkt;
  uint32_t bytes = (hdr->len);
  uint16_t u16HeaderLen = (pkt[2] + (pkt[3] << 8)); // variable radiotap header size
  uint32_t dataLen = bytes - u16HeaderLen - sizeof(crc);
  uint32_t captlimit = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(uint32_t); // 4 bytes CRC32
										      
  if (bytes >= captlimit) {
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

      const uint8_t *s = &pkt[u16HeaderLen]; // compute CRC32 for [sizeof(wifi_hdr) + sizeof(llc_hdr) + data]
      uint32_t crc=0xFFFFFFFF;
      for(uint32_t i=0;i<dataLen;i++) {
        uint8_t ch=s[i];
        uint32_t t=(ch^crc)&0xFF;
        crc=(crc>>8)^crc32_table[t];
      }

      uint32_t crc_rx;                       // retrieve CRC32 from last uint32_t
      memcpy(&crc_rx, &pkt[bytes - sizeof(crc_rx)], sizeof(crc_rx));
     
      if (crc_rx!=~crc)rx_status.wrong_crc_cnt++;
      else {
        uint32_t payloadSize = bytes - captlimit;
        const uint8_t *pu8 = &pkt[captlimit - sizeof(uint32_t)];
	if (payloadSize > 0) {
          uint32_t inl;
	  memcpy(&inl,pu8, sizeof(inl));
	  pu8 += sizeof(inl);
          write(STDOUT_FILENO, pu8, inl);
	}
      }
    }
  }
}

/*****************************************************************************/
void build_crc32_table(void) {
  for(uint32_t i=0;i<256;i++) {
    uint32_t ch=i;
    uint32_t crc=0;
    for(uint32_t j=0;j<8;j++) {
      uint32_t b=(ch^crc)&1;
      crc>>=1;
      if(b) crc=crc^0xEDB88320;
      ch>>=1;
    }
    crc32_table[i]=crc;
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

  build_crc32_table();

  pcap_loop(ppcap, 0, captured_packet, NULL);
  return 0;
}
