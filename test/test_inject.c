#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static const uint8_t radiotap_hdr[] = {
  0x00, 0x00, // <-- radiotap version
  0x00, 0x00, // <- radiotap header length
  0x6f, 0x08, 0x00, 0x00, // <-- bitmap
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
  0x00, // <-- flags
  0x48, // <-- rate 36 Mb
  0x71, 0x09, 0xc0, 0x00, // <-- channel
  0xde, // <-- antsignal
  0x00, // <-- antnoise
  0x01, // <-- antenna
};

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
