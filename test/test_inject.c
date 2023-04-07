#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static const uint8_t radiotap_hdr[] = {
	0x00, 0x00, // <-- radiotap version + pad byte
	0x0b, 0x00, // <- radiotap header length
	0x04, 0x0c, 0x00, 0x00, // <-- bitmap
	0x60, // <-- rate (in 500kHz units)
	0x0c, //<-- tx power
	0x01 //<-- antenna
};

/*
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

// For MCS#1 -- QPSK 1/2 20MHz long GI + STBC
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT))

// for MCS#1 -- QPSK 1/2 20MHz long GI without STBC
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20)

// for stbc + ldpc: https://en.wikipedia.org/wiki/Space%E2%80%93time_block_code
#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT) | IEEE80211_RADIOTAP_MCS_FEC_LDPC)

#define MCS_INDEX  1

static uint8_t radiotap_hdr[]  __attribute__((unused)) = {
    0x00, 0x00, // <-- radiotap version
    0x0d, 0x00, // <- radiotap header length
    0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
    0x08, 0x00,  // RADIOTAP_F_TX_NOACK
    MCS_KNOWN , MCS_FLAGS, MCS_INDEX // bitmap, flags, mcs_index
};


*/

static const char wifi_hdr[] = {
  0x88, 0x00, 0x30, 0x00,             // frame type to match on receiver
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // port to be set and to match on receiver
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xc0, 0x20, 0x20, 0x00
};

static const uint8_t llc_hdr[] = {
  0xaa, 0xaa, 0x03,
  0x00, 0x00, 0x00,
  0x88, 0xb5
};

typedef struct {
  uint16_t seq_blk_nb;
  uint16_t len;
} pay_hdr_t;


#define PKT_SIZE_MAX 2325
#define PKT_SIZE 1510
#define PKT_DATA (PKT_SIZE - sizeof(radiotap_hdr) - sizeof(wifi_hdr) - sizeof(llc_hdr) - sizeof(pay_hdr_t))
#define PKT_PAY  (PKT_DATA - sizeof(uint64_t))

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t buf[PKT_SIZE];
  uint8_t *pu8 = buf;
  uint8_t portId = 5;

  memcpy(buf, radiotap_hdr, sizeof(radiotap_hdr));
  buf[2] = (sizeof(radiotap_hdr));
  pu8 += sizeof(radiotap_hdr);
  memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
  pu8[5] = portId;
  pu8 += sizeof(wifi_hdr);
  memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  pu8 += sizeof(llc_hdr);
  uint8_t hdr_len = pu8 - buf;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);

  uint8_t *pu8_payload_head = pu8;
//  pu8 += sizeof(pay_hdr_t);

  uint16_t inl, len, ret, seq = 0;

  struct timespec start;
  uint64_t start_n ;

  uint32_t total_in = 0, total_out=0, total_cpt=0;

  fd_set rfds;
  uint8_t headerSize = sizeof(radiotap_hdr) + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(pay_hdr_t) +  sizeof(uint64_t);

  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL); 
    if (ret > 0) {

      pu8 = pu8_payload_head + sizeof(pay_hdr_t); 

      inl = read(STDIN_FILENO, pu8, PKT_PAY);   // fill pkts with read input
      if (inl < 0) continue;
      if (inl == 0) {printf("total cpt(%d) in(%d) out(%d)\n",total_cpt,total_in,total_out);exit(0);}
      total_in += inl;

      clock_gettime( CLOCK_MONOTONIC, &start);
      start_n = (start.tv_nsec + (start.tv_sec * 1000000000L));

      memcpy(pu8, &start_n, sizeof(uint64_t));
      pu8 += sizeof(uint64_t);

      (((pay_hdr_t *)pu8_payload_head)->seq_blk_nb) = seq ++;
      (((pay_hdr_t *)pu8_payload_head)->len) = inl;

      len = inl + headerSize;
      ret = pcap_inject(ppcap, buf, len);
      total_out += ret;
      total_cpt ++;
    }
  }
}
