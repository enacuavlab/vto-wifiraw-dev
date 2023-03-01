#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

int packets;

/*****************************************************************************/
typedef struct {
  int header_lg;
  pcap_t *ppcap;
} interface_t;

/*****************************************************************************/
void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

  struct udphdr *udphdr;
  struct ip *iphdr;
  char iphdrInfo[256], srcip[256], dstip[256];

  interface_t *inter = (interface_t *)user;

  packetptr += inter->header_lg;
  iphdr = (struct ip*)packetptr;

  strcpy(srcip, inet_ntoa(iphdr->ip_src));
  strcpy(dstip, inet_ntoa(iphdr->ip_dst));

  sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
    ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
    4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
  packetptr += 4*iphdr->ip_hl;
  if ((iphdr->ip_p) == IPPROTO_UDP) {

    udphdr = (struct udphdr*)packetptr;
    printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
      dstip, ntohs(udphdr->uh_dport));
    printf("%s\n", iphdrInfo);
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
    packets += 1;
  }
}


/*****************************************************************************/
int sighandler(const int signal, void *ptr) {
  static interface_t *saved = NULL;
 
  if (saved == NULL) saved = ptr; // initialization
  else {
    struct pcap_stat stats;
    if (pcap_stats(saved->ppcap, &stats) >= 0) {
      printf("\n%d packets captured\n", packets);
      printf("%d packets received\n", stats.ps_recv);
      printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_close(saved->ppcap);
    exit(0);
  }

  return(0);
}


/*****************************************************************************/
int main(int argc, char *argv[]) {

  if (argc != 2) exit(-1);
  char *device = argv[1];
  interface_t inter;

  /* hack to add parameters to signal */
  signal(SIGINT,  (void (*)(int))sighandler);
  signal(SIGTERM,  (void (*)(int))sighandler);
  signal(SIGQUIT,  (void (*)(int))sighandler);
  sighandler(0, (void *)&inter);

  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  char szProgram[512];

  int count=0;

  int linktype;
  bool ret=false;
  if ((inter.ppcap = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) != NULL) {
    if ((linktype = pcap_datalink(inter.ppcap)) != PCAP_ERROR) {
      if (linktype == DLT_EN10MB) {
	inter.header_lg = 14;
        sprintf(szProgram, "udp"); // udp port 53
	ret = true;
      }
      if (linktype == DLT_IEEE802_11_RADIO) { // match on frametype, 1st byte of mac (ff) and portnumber 
	inter.header_lg = 0x18; 
        sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", 0); // port = 0 TBC
	ret = true;
      }
    }
  }

  ret=false;
  if (pcap_compile(inter.ppcap, &bpf, szProgram, 1, 0) != PCAP_ERROR) 
    if (pcap_setfilter(inter.ppcap, &bpf) != PCAP_ERROR) ret = true;
  if (!ret) exit(-1);

  if (pcap_loop(inter.ppcap, count, packet_handler, (u_char*)&inter) < 0) exit(-1); 

  sighandler(0,&inter);
}
