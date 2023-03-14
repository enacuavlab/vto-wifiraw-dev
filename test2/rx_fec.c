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
  uint8_t *rx_p = rx_buff; 
  struct pcap_pkthdr * ppcapPacketHeader = NULL;

  wifi_adapter_rx_status_t rx_status;
  memset(&rx_status,0,sizeof(rx_status));
  fd_set readset;int ret, u16HeaderLen, n, crc;
  PENUMBRA_RADIOTAP_DATA prd;
  for(;;) {
    FD_ZERO(&readset);FD_SET(fd, &readset);
    ret = select(fd+1, &readset, NULL, NULL, NULL);
    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {
      ret = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&rx_p);
      if (ret < 0) exit(-1);
      if (ret != 1) continue;
      u16HeaderLen = (rx_p[2] + (rx_p[3] << 8));
      if (ppcapPacketHeader->len < (u16HeaderLen + n80211HeaderLength)) continue;
      int bytes = ppcapPacketHeader->len - (u16HeaderLen + n80211HeaderLength);
      if (bytes < 0) continue;
      struct ieee80211_radiotap_iterator rti;
      if (ieee80211_radiotap_iterator_init(&rti,(struct ieee80211_radiotap_header *)rx_p,ppcapPacketHeader->len,NULL)<0)continue;
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
      rx_p += u16HeaderLen + n80211HeaderLength;
      crc = (prd.m_nRadiotapFlags & 0x40) == 0;
      if(!crc) rx_status.wrong_crc_cnt++;
      rx_status.received_packet_cnt++;
      rx_status.last_update = time(NULL);

      printf("(%d)(%d)\n",bytes,crc);fflush(stdout);

//      wifi_packet_header_t *wph = (wifi_packet_header_t*)rx_p;
    }
  }
}
//  int block_num = wph->sequence_number / param_data_packets_per_block;

//  rx_p += sizeof(wifi_packet_header_t);
//  data_len -= sizeof(wifi_packet_header_t);

//  payload_header_t *ph = (payload_header_t*)rx_p;
//  rx_p += sizeof(payload_header_t);

//  int32_t temp = (ph->data_length) << 13; // fec packets have data_length signed bit set
 
//  printf("crc_corrrect (%d)\n", crc_correct);


//  if (temp > 0) {
//    write(STDOUT_FILENO, rx_p, ph->data_length);
//    fflush(stdout);
