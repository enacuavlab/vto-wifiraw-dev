#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

// radiotap.org
// nc.net.in.tum.de (network conding)
#ifdef LEGACY
static uint8_t uint8_taRadiotapHeader[] =  {
        0x00, 0x00,             // radiotap version
        0x0d, 0x00,             // radiotap header length
        0x04, 0x80, 0x00, 0x00, // radiotap present flags: 0x04 (rate), 0x80 (tx_flags)
        0x0c,                   // RATE : 0x0c (6 Mbytes), overwritten, later 
	0x00, 0x08,             // RADIOTAP_F_TX_NOACK (0x0008)     
        0x00, 0x00
};
#else
static uint8_t uint8_taRadiotapHeader[] =  {
        0x00, 0x00,             // radiotap version
        0x0d, 0x00,             // radiotap header length
        0x00, 0x80, 0x08, 0x00, // radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
        0x08, 0x00,             // RADIOTAP_F_TX_NOACK
        0x07, 0x00, 0x05,       // MCS flags (0x07), 0x0, rate index (0x05)
};
#endif

static uint8_t ieee_hdr_data[] = {
        0x08, 0x01,                         // Frame Control : Data frame from STA to DS
	0x00, 0x00,                         // Duration
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Receiver MAC 
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Transmitter MAC
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Destination MAC
        0x10, 0x86,                          // Sequence control
};

typedef struct {
  uint16_t seq;
  uint16_t len;
  uint64_t stp_n;
} __attribute__((packed)) pay_hdr_t;


//#define PKT_SIZE 2311 // 802.11 max packet size will crash the system

// From gstreamer rtph264pay mtu=1400
#define DATA_SIZE     1400
//#define DATA_SIZE       1442
// Full 802.11 transmitted packet with headers, payload
#define PKT_SIZE_0 (sizeof(uint8_taRadiotapHeader) + sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + DATA_SIZE )
// and CRC32
#define PKT_SIZE_1 (PKT_SIZE_0 + sizeof(uint32_t))
