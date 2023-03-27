#include "wfb.h"

#define payload_head (sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr) + 7 )
#define payload_data (payload_head + sizeof(uint32_t))

/*****************************************************************************/
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {

  uint32_t size = pkt[payload_head];
  uint8_t *pu8 = pkt[payload_data];

//  write(STDOUT_FILENO,&pkt[payload_data],size);
  printf("(%d)\n",size);
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

  int loop_status = pcap_loop(ppcap, 0, captured_packet, NULL);
  return 0;
}
