#include <sys/time.h>
#include <sys/resource.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "radiotap_iter.h"
#include "fec.h"

/*****************************************************************************/
static uint8_t uint8_taRadiotapHeader[] = {
  0x00, 0x00, // <-- radiotap version
  0x0c, 0x00, // <- radiotap header length
  0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
  0x00, // datarate (will be overwritten later)
  0x00,
  0x00, 0x00
};

static uint8_t uint8_taIeeeHeader_data[] = {
  0x08, 0xbf, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
  0xff, 0x00, 0x00, 0x00, 0x00, 0x00,// 1st byte of IEEE802.11 RA (mac) must be 0xff or something odd, otherwise strange things happen. second byte is the port (will be overwritten later)
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
  0x00, 0x00, // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};

/*****************************************************************************/
typedef struct {
  size_t len;
  uint8_t *data;
} pkt_t;  // packets with variable data len


typedef struct {
  time_t last_update;
  uint32_t received_packet_cnt;
  uint32_t wrong_crc_cnt;
  int8_t current_signal_dbm;
} wifi_adapter_rx_status_t;

typedef struct {
  uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;


typedef struct  {
  int m_nChannel;
  int m_nChannelFlags;
  int m_nRate;
  int m_nAntenna;
  int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;

/*****************************************************************************/
int param_fec_packets_per_block = 4;
int param_data_packets_per_block = 8;

#define PKT_SIZE 1510
#define PKT_DATA (PKT_SIZE - sizeof(uint8_taRadiotapHeader) - sizeof(uint8_taIeeeHeader_data) - sizeof(wifi_packet_header_t) - sizeof(payload_header_t))

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE]; szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 1600, 0, -1, szErrbuf);
  if (ppcap == NULL) exit(-1);
  if(pcap_setnonblock(ppcap, 1, szErrbuf) < 0) exit(-1);
  char szProgram[512];
  int port = 0; /* 0-255 */
  int nLinkEncap = pcap_datalink(ppcap);
  int n80211HeaderLength;
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
    n80211HeaderLength = 0x18;
    sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber
  } else exit(-1);
  struct bpf_program bpfprogram;
  if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(ppcap, &bpfprogram) == -1) exit(-1);
  int fd = pcap_get_selectable_fd(ppcap);

  uint8_t rx_buff[PKT_SIZE];
  uint8_t *rx_p0 = rx_buff; 
  struct pcap_pkthdr * ppcapPacketHeader = NULL;

  wifi_adapter_rx_status_t rx_status;
  memset(&rx_status,0,sizeof(rx_status));
  fd_set readset;int ret, u16HeaderLen, n, crc;
  PENUMBRA_RADIOTAP_DATA prd;

  pkt_t pkts_data[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) {pkts_data[i].data=malloc(PKT_DATA);pkts_data[i].len=0;}
  pkt_t pkts_fec[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) {pkts_fec[i].data=malloc(PKT_DATA);pkts_fec[i].len=0;}

  int di = 0,fi = 0;
  for(;;) {
    FD_ZERO(&readset);FD_SET(fd, &readset);
    ret = select(fd+1, &readset, NULL, NULL, NULL);
    if(ret == 0) break;
    if(FD_ISSET(fd, &readset)) {
      ret = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&rx_p0);
      if (ret < 0) exit(-1);
      if (ret != 1) continue;
      u16HeaderLen = (rx_p0[2] + (rx_p0[3] << 8));
      if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength)) continue;
      int bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
      if (bytes < 0) continue;
      struct ieee80211_radiotap_iterator rti;
      if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)rx_p0,ppcapPacketHeader->len,NULL)<0)continue;
      PENUMBRA_RADIOTAP_DATA prd;
      while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
        switch (rti.this_arg_index) {
          case IEEE80211_RADIOTAP_FLAGS:
            prd.m_nRadiotapFlags = *rti.this_arg;
            break;
          case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rx_status.current_signal_dbm = (int8_t)(*rti.this_arg);
            break;
        }
      }
      rx_p0 += u16HeaderLen + n80211HeaderLength;
      crc = (prd.m_nRadiotapFlags & 0x40) == 0;
      if(!crc) rx_status.wrong_crc_cnt++;
      rx_status.received_packet_cnt++;
      rx_status.last_update = time(NULL);

//      printf("(%d)\n",((wifi_packet_header_t *)rx_p0)->sequence_number);

      rx_p0 += sizeof(wifi_packet_header_t);
      uint32_t len = (((payload_header_t*)rx_p0)->data_length);
      int32_t temp = (len << 13); // fec packets have data_length signed bit set
      rx_p0 += sizeof(payload_header_t);

      if (temp > 0) { memcpy(&pkts_data[di].data,rx_p0,len);pkts_data[di].len=len;di++; }
      else { memcpy(&pkts_fec[fi].data,rx_p0,len);fi++; }

      if ((di == param_data_packets_per_block) && (fi == param_fec_packets_per_block)) {
	for (int i=0;i<param_data_packets_per_block;i++) {
          write(STDOUT_FILENO, &pkts_data[i].data,  pkts_data[i].len);
          fflush(stdout);
	}
        di=0;fi=0;
      } 
    }
  }
}
