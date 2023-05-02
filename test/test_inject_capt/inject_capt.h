#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

static const uint8_t uint8_taRadiotapHeader[] = 
{
	0x00, 0x00, // <-- radiotap version
	0x1c, 0x00, // <- radiotap header length
	0x6f, 0x08, 0x08, 0x00, // <-- bitmap
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp NOT USED !
	0x00, // <-- flags (Offset +0x10)
	0x6c, // <-- rate (0ffset +0x11)
	0x71, 0x09, 0xc0, 0x00, // <-- channel
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna
	0x07, 0x00, 0x05,  // <-- MCS flags (0x07), 0x0, rate index (0x05)
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
//#define DATA_SIZE     1400
#define DATA_SIZE       1442
// Full 802.11 transmitted packet with headers, payload
#define PKT_SIZE_0 (sizeof(uint8_taRadiotapHeader) + sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + DATA_SIZE )
// and CRC32
#define PKT_SIZE_1 (PKT_SIZE_0 + sizeof(uint32_t))
