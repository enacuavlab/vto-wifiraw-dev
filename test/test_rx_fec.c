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
  uint16_t seq_blk_nb;
  uint16_t len;
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

  bool interl = true, reset=false; 
  uint8_t *pu8, *pu8pay; 
  uint8_t di=0, ki=0;
  pkt_t pkt_d[fec_d],pkt_k[fec_k];

  uint32_t crc, crc_rx,  bytes, dataLen, captlimit, payloadSize, tmp32;
  uint16_t u16HeaderLen, seq_blk_nb, len;
 
  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    int n = select(fd+1, &readset, NULL, NULL, NULL);
    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()

      if (1 == pcap_next_ex(ppcap, &hdr, (const u_char**)(&pu8))) { // pcap_next_ex() makes its memory allocation 
          						            // we must copy this memmory before make the next call
	pu8pay = pu8;

        bytes = (hdr->len);
        u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
        dataLen = bytes - u16HeaderLen - sizeof(crc);
        captlimit = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(pay_hdr_t); // 4 bytes CRC32
  
        rx_status.rcv_pkt_cnt ++;
        if (bytes >= captlimit) {

          payloadSize = bytes - captlimit;
          if (payloadSize > 0) {

            pu8pay = pu8 + captlimit - sizeof(pay_hdr_t);
            seq_blk_nb = (((pay_hdr_t *)pu8pay)->seq_blk_nb);
            len = (((pay_hdr_t *)pu8pay)->len);

	    if (len != 0x8000) { // this is a dataframe
	  
	      if (interl) {

	        if (di < fec_d) {

    	          pkt_d[di].len = len;
  	          memcpy(&(pkt_d[di].buf), pu8pay, len);
  
    	          const uint8_t *s = &pu8[u16HeaderLen]; // compute CRC32 from variable headerlength
                  uint32_t crc=0xFFFFFFFF;
                  for(uint32_t i=0;i<dataLen;i++) {
                    uint8_t ch=s[i];
                    uint32_t t=(ch^crc)&0xFF;
                    crc=(crc>>8)^crc32_table[t];
                  }
  		  memcpy(&crc_rx,  (pu8 + bytes - sizeof(crc_rx)), sizeof(crc_rx)); // retrieve CRC32 from reveived data
    	          pkt_d[di].crc = (crc_rx == ~crc); // compare both for validity check
                  interl = !interl;
  		  di++;
  
  		  printf("(%d)(%d)\n",crc_rx,~crc);

		} else reset = true;
	      } else reset=true;

	    } else {  // This is a FEC

	      if (!interl) {

	        if (ki < fec_k) {

    	          pkt_k[ki].len = PKT_DATA;
//  	          memcpy(pkt_k[ki].buf, pu8pay, len);
		  interl = !interl;
		  ki++;

		} else reset = true;
	      } else reset = true;
	    }
	  }
	}
      }
      if (reset) { di = 0; ki = 0; reset=false; }
    }
  }
}
/*
	    } else {
  	      if (di > (d_last_ok - 1)) {
  	        if (d_valid) {
                  if (pkt_d[di].crc) {
    	  	    d_last_ok = di;
                    rx_status.signal_dbm = pu8pay[RADIOTAP_DBM_ANTSIGNAL_OFFSET];
                    write(STDOUT_FILENO, pu8, inl);
    	        } else {
    	  	  d_valid = false;
    	          rx_status.wrong_crc_cnt++;
  		}
  	      } else {
                  if ((di == fec_d) && (ki == fec_k)) {
                    for (int i = (d_last_ok + 1) ; i<fec_d; i++) {
                      write(STDOUT_FILENO, (pkt_d[i].buf) + sizeof(uint32_t), pkt_d[i].len);
                    }
		    di = 0; ki = 0; d_last_ok = 0, d_valid = true; interl = true;
		  }
  		}
	      }
  	    }
*/
