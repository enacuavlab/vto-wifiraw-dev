#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>


static uint8_t uint8_taRadiotapHeader[] =  {
	0x00, 0x00,             // radiotap version
	0x0d, 0x00,             // radiotap header length
        0x00, 0x80, 0x08, 0x00, // radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
	0x08, 0x00,             // RADIOTAP_F_TX_NOACK
	0x07, 0x00, 0x04,       // MCS flags (0x07), 0x0, rate index (0x05)
};

static uint8_t ieee_hdr_data[] = {
        0x08, 0x01,                         // Frame Control : Data frame from STA to DS
        0x00, 0x00,                         // Duration
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Receiver MAC 
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Transmitter MAC
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Destination MAC
        0x10, 0x86                          // Sequence control
};

typedef struct {
  uint16_t seq;
  uint16_t len;
  uint64_t stp_n;
} __attribute__((packed)) pay_hdr_t;


//#define PKT_SIZE 2311 // 802.11 max packet size will crash the system

// From gstreamer rtph264pay mtu=1400
#define DATA_SIZE     1400
// Full 802.11 transmitted packet with headers, payload
#define PKT_SIZE_0 (sizeof(uint8_taRadiotapHeader) + sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + DATA_SIZE )
// and CRC32
#define PKT_SIZE_1 (PKT_SIZE_0 + sizeof(uint32_t))

#define FEC_K 0
#define FEC_N 8
#define FEC_D (FEC_N - FEC_K)

/*****************************************************************************/
uint32_t crc32_table[256];

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
