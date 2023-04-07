#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>

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
#define	IEEE80211_RADIOTAP_MCS_STBC_MASK  0x60
#define	IEEE80211_RADIOTAP_MCS_STBC_1  1
#define	IEEE80211_RADIOTAP_MCS_STBC_2  2
#define	IEEE80211_RADIOTAP_MCS_STBC_3  3
#define	IEEE80211_RADIOTAP_MCS_STBC_SHIFT 5

#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

// For MCS#1 -- QPSK 1/2 20MHz long GI + STBC
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT))

//for MCS#1 -- QPSK 1/2 20MHz long GI without STBC
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20)

// for stbc + ldpc: https://en.wikipedia.org/wiki/Space%E2%80%93time_block_code
#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT) | IEEE80211_RADIOTAP_MCS_FEC_LDPC)

#define MCS_INDEX 1

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

uint32_t crc32_table[256];

/*****************************************************************************/
#define RADIOTAP_DBM_ANTSIGNAL_OFF 22

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

  build_crc32_table();
  int fd = pcap_get_selectable_fd(ppcap);

  struct timespec start,end;

  uint32_t total_in=0, total_out=0, total_cpt=0;
  
  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    int n = select(fd+1, &readset, NULL, NULL, NULL);
    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()

      struct pcap_pkthdr *hdr = NULL;
      struct pcap_pkthdr hdr2;
      uint8_t *pkt;
    
      if (1 == pcap_next_ex(ppcap, &hdr, (const u_char**)&pkt)) {

	clock_gettime( CLOCK_MONOTONIC, &start);
        uint64_t start_n = (start.tv_nsec + (start.tv_sec * 1000000000L));

        uint32_t crc;
        uint32_t bytes = (hdr->len);
        uint16_t u16HeaderLen = (pkt[2] + (pkt[3] << 8)); // variable radiotap header size
        uint32_t dataLen = bytes - u16HeaderLen - sizeof(crc);
        uint32_t captlimit = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr) + sizeof(pay_hdr_t); // 4 bytes CRC32

	total_in += bytes;

        if (bytes >= captlimit) {
      
          const uint8_t *s = &pkt[u16HeaderLen]; // compute CRC32 for [sizeof(wifi_hdr) + sizeof(llc_hdr) + data]
          uint32_t crc=0xFFFFFFFF;
          for(uint32_t i=0;i<dataLen;i++) {
            uint8_t ch=s[i];
            uint32_t t=(ch^crc)&0xFF;
            crc=(crc>>8)^crc32_table[t];
          }
      
          uint32_t crc_rx;                 // retrieve CRC32 from last uint32_t
          memcpy(&crc_rx, &pkt[bytes - sizeof(crc_rx)], sizeof(crc_rx));
        
          if (crc_rx!=~crc) printf("wrong_crc\n");
          else {
            uint32_t payloadSize = bytes - captlimit;
            const uint8_t *pu8 = &pkt[captlimit - sizeof(pay_hdr_t)];
            if (payloadSize > 0) {
              uint16_t seq_blk_nb = (((pay_hdr_t *)pu8)->seq_blk_nb);
              uint16_t len = (((pay_hdr_t *)pu8)->len);
      	      pu8 += sizeof(pay_hdr_t);
	      uint64_t end_n;
	      memcpy(&end_n,pu8,sizeof(uint64_t));

	      total_out += len;
	      total_cpt ++;
	      printf("total nb(%d) in(%d) out(%d)\n",total_cpt,total_in,total_out);
//              write(STDOUT_FILENO, pu8, len);
            }
          }
	}
      }
    }
  }
}
