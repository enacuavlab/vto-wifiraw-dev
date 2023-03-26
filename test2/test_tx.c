#include <time.h>

//#include "wfb.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <fcntl.h>

#define IEEE80211_RADIOTAP_MCS_HAVE_BW    0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS   0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI    0x04
#define IEEE80211_RADIOTAP_MCS_HAVE_FMT   0x08

#define IEEE80211_RADIOTAP_MCS_BW_20    0
#define IEEE80211_RADIOTAP_MCS_BW_40    1
#define IEEE80211_RADIOTAP_MCS_BW_20L   2
#define IEEE80211_RADIOTAP_MCS_BW_20U   3
#define IEEE80211_RADIOTAP_MCS_SGI      0x04
#define IEEE80211_RADIOTAP_MCS_FMT_GF   0x08

#define IEEE80211_RADIOTAP_MCS_HAVE_FEC   0x10
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC  0x20
#define IEEE80211_RADIOTAP_MCS_FEC_LDPC   0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK  0x60
#define IEEE80211_RADIOTAP_MCS_STBC_1  1
#define IEEE80211_RADIOTAP_MCS_STBC_2  2
#define IEEE80211_RADIOTAP_MCS_STBC_3  3
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT 5

#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

static uint8_t radiotap_header[]  __attribute__((unused)) = {
    0x00, 0x00, // <-- radiotap version
    0x0d, 0x00, // <- radiotap header length
    0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
    0x08, 0x00,  // RADIOTAP_F_TX_NOACK
    MCS_KNOWN , 0x00, 0x00 // bitmap, flags, mcs_index
};

// offset of MCS_FLAGS and MCS index
#define MCS_FLAGS_OFF 11
#define MCS_IDX_OFF 12

//the last four bytes used for channel_id
#define SRC_MAC_THIRD_BYTE 12
#define DST_MAC_THIRD_BYTE 18
#define FRAME_SEQ_LB 22
#define FRAME_SEQ_HB 23

// WFB-NG MAC address format: "W:B:X:X:X:X" where XXXX is channel_id
// channel_id = (link_id << 8) + radio_port
// First address byte 'W'(0x57) has two lower bits set that means that address is multicast and locally administred
// See https://en.wikipedia.org/wiki/MAC_address for reference

static uint8_t ieee80211_header[] __attribute__((unused)) = {
    0x08, 0x01, 0x00, 0x00,               // data frame, not protected, from STA to DS via an AP
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // receiver is broadcast
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,   // last four bytes will be replaced by channel_id
    0x00, 0x00,                           // (seq_num << 4) + fragment_num
};

/*****************************************************************************/
typedef struct {
  uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem

#define PKT_SIZE 1510
#define PKT_DATA (PKT_SIZE - sizeof(radiotap_header) - sizeof(ieee80211_header) - sizeof(payload_header_t))
//#define PKT_DATA (PKT_SIZE - sizeof(uint8_taRadiotapHeader) - sizeof(uint8_taIeeeHeader_data) - sizeof(wifi_packet_header_t) - sizeof(payload_header_t))

/*****************************************************************************/
int main(int argc, char *argv[]) {

  printf("%ld\n",sizeof(radiotap_header));
  printf("%ld\n",sizeof(ieee80211_header));
  printf("%ld\n",sizeof(payload_header_t));

  setpriority(PRIO_PROCESS, 0, -10);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);

//  uint8_taRadiotapHeader[8]=0x48; /* (0x48 x 500 kbps) = data rate : 36Mb/s 
//  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) 
//  int headerSize1 = sizeof(radiotap_header) + sizeof (ieee80211_header);
//  int headerSize2 = headerSize1 + sizeof(wifi_packet_header_t);
//  int headerSize3 = headerSize2 + sizeof(payload_header_t);

  uint8_t buf[PKT_SIZE];
  uint8_t *pu8 = buf;
  memcpy(buf, radiotap_header, sizeof(radiotap_header));
  pu8 += sizeof(radiotap_header);
  memcpy(pu8, ieee80211_header, sizeof(ieee80211_header));
  pu8 += sizeof(ieee80211_header);

  uint32_t channel_id_be = 0;
  memcpy(pu8 + SRC_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));
  memcpy(pu8 + DST_MAC_THIRD_BYTE, &channel_id_be, sizeof(uint32_t));

  uint32_t ieee80211_seq = 0;
  pu8[FRAME_SEQ_LB] = ieee80211_seq & 0xff;
  pu8[FRAME_SEQ_HB] = (ieee80211_seq >> 8) & 0xff;
  ieee80211_seq += 16;
  pu8 += sizeof(ieee80211_header);

  fd_set rfds;
  struct timeval timeout;

  int ret;
  int nb_seq=0;
  uint32_t inl = 0;

  uint8_t *pu8_payload_header = pu8;
  pu8 += sizeof(payload_header_t);

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {

      inl=read(STDIN_FILENO, pu8, PKT_DATA);   // fill pkts with read input
      if (inl < 0) continue;

      (((payload_header_t *)pu8_payload_header)->data_length) = inl;

      ret = pcap_inject(ppcap, buf, PKT_SIZE);
      printf("(%d)(%d)(%d)\n", nb_seq, ret,inl);fflush(stdout);

      nb_seq++;
    }
  }
}
