#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "radiotap_iter.h"

int packets;

/*****************************************************************************/
typedef struct {
  pcap_t *ppcap;
  int header_lg;
  int wrong_crc_cnt;
  int received_packet_cnt;
} interface_t;


typedef struct  {
        int m_nChannel;
        int m_nChannelFlags;
        int m_nRate;
        int m_nAntenna;
        int m_nRadiotapFlags;
} __attribute__((packed)) radiotap_t;


typedef struct {
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;

/*****************************************************************************/
int param_data_packets_per_block = 4;
int param_fec_packets_per_block = 2;

/*****************************************************************************/
void process_payload_811(const u_char *data, size_t data_len, int crc_correct) {

  wifi_packet_header_t *wph = (wifi_packet_header_t*)data;
  data += sizeof(wifi_packet_header_t);
  data_len -= sizeof(wifi_packet_header_t);

  int block_num = wph->sequence_number / (param_data_packets_per_block+param_fec_packets_per_block);

  printf("seq %x blk %x crc %d len %ld\n",wph->sequence_number,block_num,crc_correct,data_len);

}

/*****************************************************************************/
void packet_handler_811(u_char *user, const struct pcap_pkthdr *ppcapPacketHeader, const u_char *pu8Payload) {

  int u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

  interface_t *inter = (interface_t *)user;
  if (ppcapPacketHeader->len < (u16HeaderLen + inter->header_lg)) return; // header_lg = n80211HeaderLength
 
  int bytes = ppcapPacketHeader->len - (u16HeaderLen + inter->header_lg);
  if (bytes < 0) return;

  struct ieee80211_radiotap_iterator rti;
  if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)pu8Payload,
			               ppcapPacketHeader->len,NULL) < 0) return;
  radiotap_t prd;
  int current_signal_dbm=0;
  int n=0;
  while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
    switch (rti.this_arg_index) {
      case IEEE80211_RADIOTAP_FLAGS:
        prd.m_nRadiotapFlags = *rti.this_arg;
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        current_signal_dbm = (int8_t)(*rti.this_arg);
        break;
    }
  }

  pu8Payload += u16HeaderLen + inter->header_lg;
  int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;
  if(!checksum_correct) inter->wrong_crc_cnt++;
  inter->received_packet_cnt++;

  //printf("dbm %d wrong %d rcv %d\n", current_signal_dbm,inter->wrong_crc_cnt,inter->received_packet_cnt);

  process_payload_811(pu8Payload, bytes, checksum_correct);
}

/*****************************************************************************/
void packet_handler_udp(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

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
  memset(&inter,0,sizeof(inter));

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
  pcap_handler packet_handler;
  bool ret=false;
  if ((inter.ppcap = pcap_open_live(device, 1600, 0, -1, errbuf)) != NULL) { // promiscous
    if ((linktype = pcap_datalink(inter.ppcap)) != PCAP_ERROR) {
      if (linktype == DLT_EN10MB) {
	inter.header_lg = 14;
        sprintf(szProgram, "udp"); // udp port 53
        packet_handler = packet_handler_udp;
	ret = true;
      }
      if (linktype == DLT_IEEE802_11_RADIO) { // match on frametype, 1st byte of mac (ff) and portnumber 
	inter.header_lg = 0x18; //  length of standard IEEE802.11 data frame header is 24 bytes = 0x18
        sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", 0); // port = 0 TBC
        packet_handler = packet_handler_811;
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
