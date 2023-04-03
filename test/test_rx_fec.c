#include "wfb.h"

/*****************************************************************************/
typedef struct {
  uint32_t rcv_pkt_cnt;
  uint32_t wrong_crc_cnt;
  int8_t signal_dbm;
} wifi_adapter_rx_status_t;
wifi_adapter_rx_status_t rx_status;


typedef struct {
  bool crc;
  uint32_t len;          // payload length
  uint8_t buf[PKT_DATA]; // payload data         
} pkt_t;

/*****************************************************************************/
#define RADIOTAP_DBM_ANTSIGNAL_OFFSET 22

uint32_t crc32_table[256];
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

  int fd = pcap_get_selectable_fd(ppcap);

  struct pcap_pkthdr *hdr = NULL;
  pkt_t pkt_d[fec_d],pkt_k[fec_k];
  uint8_t cpt_d=0, cpt_k=0, cpt_d_last_ok=0;
  uint8_t *pu8,*pu8pay;

  uint32_t crc, crc_rx,  bytes, dataLen, captlimit, payloadSize, inl;
  uint16_t u16HeaderLen;
  bool data_valid = true;
 
  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    int n = select(fd+1, &readset, NULL, NULL, NULL);
    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()

      if (1 == pcap_next_ex(ppcap, &hdr, (const u_char**)&(pu8))) {  // pcap_next_ex() makes its memory allocation 
        pu8pay = pu8;						     // we must copy this memmory before make the next call
        bytes = (hdr->len);
        u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
        dataLen = bytes - u16HeaderLen - sizeof(crc);
        captlimit = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(uint32_t); // 4 bytes CRC32
  
        rx_status.rcv_pkt_cnt ++;
        if (bytes >= captlimit) {

          payloadSize = bytes - captlimit;
          if (payloadSize > 0) {
            pu8 = pu8 + captlimit - sizeof(uint32_t);
            memcpy(&inl,pu8, sizeof(inl));
            pu8 += sizeof(inl);

            if ((int16_t)inl < 0) {
	      if (cpt_k < fec_k) {
                pkt_k[cpt_k].len = -inl;
	        memcpy(pkt_k[cpt_k].buf, pu8, -inl); 
	        cpt_k++;
	      }
	    } else { // This is for data frames
	      if (cpt_d < fec_d) {
  	        pkt_d[cpt_d].len = inl;
	        memcpy(pkt_d[cpt_d].buf, pu8, inl);
  	        const uint8_t *s = pu8pay + u16HeaderLen; // compute CRC32 from variable headerlength
                uint32_t crc=0xFFFFFFFF;
                for(uint32_t i=0;i<dataLen;i++) {
                  uint8_t ch=s[i];
                  uint32_t t=(ch^crc)&0xFF;
                  crc=(crc>>8)^crc32_table[t];
                }
                memcpy(&crc_rx,  (pu8pay + bytes - sizeof(crc_rx)), sizeof(crc_rx)); // retrieve CRC32 from reveived data
  	        pkt_d[cpt_d].crc = (crc_rx == ~crc); // compare both for validity check
		cpt_d++;
              }
	    }

	    if (cpt_d == fec_d) {
	      if (data_valid) {
                if (pkt_d[cpt_d].crc) {
  	  	  cpt_d_last_ok = cpt_d;
                  rx_status.signal_dbm = pu8pay[RADIOTAP_DBM_ANTSIGNAL_OFFSET];
                  write(STDOUT_FILENO, pu8, inl);
  	        } else {
  	  	  data_valid = false;
  	          rx_status.wrong_crc_cnt++;
		}
	      } else {
                if ((cpt_k == fec_k) && (cpt_d == fec_d)) {
                  for (int i = cpt_d_last_ok ; i<fec_d; i++) {
                    write(STDOUT_FILENO, (pkt_d[i].buf) + sizeof(uint32_t), pkt_d[i].len);
                  }
		}
	      }
	    }
	  }
        }
      }
    }
  }
}
