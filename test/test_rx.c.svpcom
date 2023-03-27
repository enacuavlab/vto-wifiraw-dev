#include <sys/resource.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <pcap.h>


/*****************************************************************************/
typedef struct {
  uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem

/*****************************************************************************/
void captured_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *pkt) {

  uint8_t *pu8 = pkt;
  uint32_t inl = (((payload_header_t *)pu8)->data_length);
  printf("CAPTURED (%d)\n",inl);
  for (int i=0;i<45;i++) printf(" %x ",pkt[i]);
  printf("\n");fflush(stdout);
}
/*
  int u16HeaderLen = (pkt[2] + (pkt[3] << 8));
  if (!(hdr->len < (u16HeaderLen + n80211HeaderLength))) {
    int bytes = hdr->len - (u16HeaderLen + n80211HeaderLength);
    if (bytes >= 0) {
      printf("(%d)\n",bytes);fflush(stdout);
//        crc = ((prd.m_nRadiotapFlags & 0x40) == 0);
//    rx_p0 += u16HeaderLen + n80211HeaderLength;

    }
  }
}
*/
/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  struct pcap_pkthdr *hdr;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpfprogram;
  char szProgram[512];
  int port = 0;
  uint8_t rx_buff[4096];
  uint8_t *rx_p = rx_buff;
  int ret;
  fd_set readset;

  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0)       exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0)         exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0)         exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0)  exit(-1);
  if (pcap_activate(ppcap) !=0)                exit(-1);
  if (pcap_setnonblock(ppcap, 1, errbuf) != 0) exit(-1);

  uint32_t channel_id = 0;
  int nLinkEncap = pcap_datalink(ppcap);
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
//    n80211HeaderLength = 0x18;
    sprintf(szProgram, "ether[0x0a:2]==0x5742");
//    sprintf(szProgram, "ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x%08x", channel_id); // chane
//    sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber
  } else exit(-1);
  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) exit(-1);
  pcap_freecode(&bpfprogram);

//    program = string_format("ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x%08x", channel_id);

  printf("RUNNING\n");fflush(stdout);
  int loop_status = pcap_loop(ppcap, 0, captured_packet, NULL);
  return 0;
}
