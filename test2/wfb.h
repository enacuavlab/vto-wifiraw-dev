#ifndef __WFB_H
#define __WFB_H

#include <sys/time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <fcntl.h>
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
    uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t; // no padding between fields. 


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t; // idem


/*****************************************************************************/
//int fec_k = 0; // NO FEC
int fec_k = 4;
int fec_n = 8;

#define PKT_SIZE 1510
#define PKT_DATA (PKT_SIZE - sizeof(uint8_taRadiotapHeader) - sizeof(uint8_taIeeeHeader_data) - sizeof(wifi_packet_header_t) - sizeof(payload_header_t))

#endif /* __WFB_H */

