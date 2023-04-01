#include "wfb.h"

/*****************************************************************************/
typedef struct {
  uint32_t rcv_pkt_cnt;
  uint32_t wrong_crc_cnt;
  int8_t signal_dbm;
} wifi_adapter_rx_status_t;
wifi_adapter_rx_status_t rx_status;


uint32_t crc32_table[256];

typedef struct {
  bool crc;
  uint16_t len;
  uint8_t pay[PKT_DATA];
} pkt_t;
pkt_t pkt_fec[fec_k],pkt_data[fec_d];
uint8_t cpt_fec=0,cpt_data=0,cpt_send=0;
uint32_t crc_data=0;

/*****************************************************************************/
#define RADIOTAP_DBM_ANTSIGNAL_OFF 22

/*****************************************************************************/
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {

  uint32_t crc;
  uint32_t bytes = (hdr->len);
  uint16_t u16HeaderLen = (pkt[2] + (pkt[3] << 8)); // variable radiotap header size
  uint32_t dataLen = bytes - u16HeaderLen - sizeof(crc);
  uint32_t captlimit = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(uint32_t); // 4 bytes CRC32

  rx_status.rcv_pkt_cnt ++;  

  if (bytes >= captlimit) {
    uint32_t payloadSize = bytes - captlimit;
    if (payloadSize > 0) {
      const uint8_t *pu8 = &pkt[captlimit - sizeof(uint32_t)];
      uint16_t len;
      memcpy(&len,pu8, sizeof(len));
      pu8 += sizeof(len);
      int16_t tmp = (len << 8); // dispatch data frames and fec frames
      if (tmp < 0) {

        const uint8_t *s = &pkt[u16HeaderLen]; // compute CRC32 for [sizeof(wifi_hdr) + sizeof(llc_hdr) + data]
        uint32_t crc=0xFFFFFFFF;
        for(uint32_t i=0;i<dataLen;i++) {
          uint8_t ch=s[i];
          uint32_t t=(ch^crc)&0xFF;
          crc=(crc>>8)^crc32_table[t];
        }

        uint32_t crc_rx;                 // retrieve CRC32 from last uint32_t
        memcpy(&crc_rx, &pkt[bytes - sizeof(crc_rx)], sizeof(crc_rx));

        memcpy(pkt_data[cpt_data].pay, pu8, len);
        pkt_data[cpt_data].len = len;
        pkt_data[cpt_data].crc = (crc_rx==~crc);
	cpt_data++;

        if (pkt_data[cpt_data].crc) {
          rx_status.signal_dbm = pkt[RADIOTAP_DBM_ANTSIGNAL_OFF];
          write(STDOUT_FILENO,pu8,len);
          fflush(stdout);
	  cpt_send++;
	} else {
          rx_status.wrong_crc_cnt++;
	  crc_data |=1 << cpt_data; // starting at 1
	}

      } else {
        memcpy(pkt_fec[cpt_fec].pay, pu8, PKT_DATA);
	cpt_fec++;
      }

      if (cpt_fec == fec_k) {
	cpt_data=0;cpt_fec=0;cpt_send=0;
	crc_data=0;
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
