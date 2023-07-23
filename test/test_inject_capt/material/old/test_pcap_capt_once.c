#include <pcap.h>

#include "capt_inject.h"

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

  int fd = pcap_get_selectable_fd(ppcap);

  struct timespec curr;
  struct pcap_pkthdr *hdr = NULL;
  uint64_t stp_n, curr_n; 
  float delta_m;
  uint16_t n, u16HeaderLen,len,seq;
  uint8_t *pu8,payload;
  
  fd_set readset;
  FD_ZERO(&readset);
  FD_SET(fd, &readset);
  n = select(fd+1, &readset, NULL, NULL, NULL);
  if(n == 0) exit(-1);
  if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()

    if (1 == pcap_next_ex(ppcap, &hdr, (const u_char**)&pu8)) {

      clock_gettime( CLOCK_MONOTONIC, &curr);

      u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
      payload = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr);

      pu8 += payload;
      seq = (((pay_hdr_t *)pu8)->seq); 
      len = (((pay_hdr_t *)pu8)->len); 
      stp_n = (((pay_hdr_t *)pu8)->stp_n);

      curr_n = (curr.tv_nsec + (curr.tv_sec * 1000000000L));
      delta_m = (float)(curr_n - stp_n) / 1000000;
      
      printf("(%d)(%d)\n",seq,len);
      printf("(%ld)\n",stp_n);
      printf("(%.03f)\n",delta_m);
    }
  }
}
