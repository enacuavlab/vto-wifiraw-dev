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
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
        0x00, // datarate (will be overwritten later in packet_header_init)
        0x00,
        0x00, 0x00
};
static uint8_t ieee_hdr_data[] =
{
        0x08, 0xbf, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00,// 1st byte of IEEE802.11 RA (mac) must be 0xff or something odd, otherwise strange things happen. second byte is the port (will be overwritten later)
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
        0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
        0x00, 0x00, // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};


/*
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
	0x07, 0x00, 0x03,  // <-- MCS flags (0x07), 0x0, rate index (0x03)
};

static uint8_t ieee_hdr_data[] =
{
        0x08, 0x02, 0x00, 0x00,             // FC 0x0801. 0--subtype; 8--type&version; 02--toDS0 fromDS1 (data packet from DS to STA)
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // BSSID/MAC of AP
        0x66, 0x55, 0x44, 0x33, 0x22, 0x22, // Source address (STA)
        0x66, 0x55, 0x44, 0x33, 0x22, 0x33, // Destination address (another STA under the same AP)
        0x10, 0x86,                         // 0--fragment number; 0x861=2145--sequence number
};
*/

typedef struct {
  uint16_t seq;
  uint16_t len;
  uint64_t stp_n;
} __attribute__((packed)) pay_hdr_t;
//} pay_hdr_t;


//#define PKT_SIZE 2311 // 802.11 max packet size will crash the system

// From gstreamer rtph264pay mtu=1400
//#define DATA_SIZE	1400 
#define DATA_SIZE	1450 
// Full 802.11 transmitted packet with headers, payload
#define PKT_SIZE_0 (sizeof(uint8_taRadiotapHeader) + sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + DATA_SIZE )
// and CRC32
#define PKT_SIZE_1 (PKT_SIZE_0 + sizeof(uint32_t))

#define FEC_K 0
#define FEC_N 8
#define FEC_D (FEC_N - FEC_K)
