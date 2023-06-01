#ifndef __WIFIRAW_COM_H
#define __WIFIRAW_COM_H

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
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
  uint8_t id;
  uint16_t seq;
  uint16_t len;
  uint64_t stp_n;
} __attribute__((packed)) pay_hdr_t;

typedef struct {
  FILE *log;
  uint8_t role;
  char node[20];
  fd_set readset;
  uint16_t maxfd;
  uint16_t fd_in[2 + 2];
  uint16_t fd_out[2 + 2];
  struct sockaddr_in addr_out[2 + 2];
} init_t;  


#define UDP_SIZE 65507
#define DATA_SIZE 1400

#define PKT_SIZE_0_IN (50 + sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + DATA_SIZE ) // Estimated variable radiotap header on reception
#define PKT_SIZE_1_IN (PKT_SIZE_0_IN + sizeof(uint32_t))

#define offset0 (sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data))
#define offset1 (sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data) + sizeof(pay_hdr_t))

extern uint32_t crc32_table[256];

void init(init_t *px) ;


#endif /* __WIFIRAW_COM_H */
