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
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>


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
  uint16_t len;  // len for the full payload not including (pay_hdr_t), and use to check crc32
  uint64_t stp_n;
} __attribute__((packed)) payhdr_t;

typedef struct {
  uint8_t id;
  uint16_t len; // len for the subpayload not including (sub_pay_hdr_t)
} __attribute__((packed)) subpayhdr_t;

typedef struct {
  FILE *log;
  uint8_t role;
  char node[20];
  fd_set readset;
  uint16_t maxfd;
  uint16_t fd[4];
  uint16_t fd_out[2];
  struct sockaddr_in addr_out[2];
} init_t;  


#define UDP_SIZE 65507

#define VIDEO_SIZE 1400
#define TELEM_SIZE 200
#define TUNEL_SIZE 200
#define DATA_SIZE (VIDEO_SIZE + TELEM_SIZE + TUNEL_SIZE)
uint16_t subpayloadmaxlen[]={VIDEO_SIZE,TELEM_SIZE,TUNEL_SIZE};

#define MAX_RADIOTAP_HEADER_SIZE  50  // Estimated variable radiotap header on reception
#define PKT_SIZE (MAX_RADIOTAP_HEADER_SIZE + sizeof(ieee_hdr_data) + sizeof(payhdr_t) + 3*sizeof(subpayhdr_t) + DATA_SIZE )
#define FULL_PKT_SIZE (PKT_SIZE + sizeof(uint32_t)) // Inclubdibg CRC32

#define offset0 (sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data))
#define offset1 (sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data) + sizeof(payhdr_t))

extern uint32_t crc32_table[256];

void init(init_t *px) ;


#endif /* __WIFIRAW_COM_H */
