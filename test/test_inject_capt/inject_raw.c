#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint16_t param_pktnb  = 2000;
  uint16_t param_pktlen = 1466;
  uint16_t param_ndelay = 400;

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t portId = 5;

  uint8_t buffer[PKT_SIZE], *ieee_hdr = ieee_hdr_data;
  uint8_t *pu8 = buffer;

  struct timespec stp;
  uint64_t stp_n;
  uint16_t r,seq=0,packet_size;

  printf("%ld\n",DATA_SIZE);
  if (param_pktlen >  DATA_SIZE) exit(-1);

  memset(buffer, 0, sizeof (buffer));
  memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  pu8 += sizeof (uint8_taRadiotapHeader);
  ieee_hdr[9] = portId;
  memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));
  pu8 += sizeof (ieee_hdr_data);

  uint16_t fd = 0;
  if (-1 == (fd=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if((r = bind(fd, (struct sockaddr *)&sll, sizeof(sll))) == -1) exit(-1);

  packet_size = PKT_SIZE;

  for(int i = 1; i <= param_pktnb; i++) {

    (((pay_hdr_t *)pu8)->seq) = seq;
    (((pay_hdr_t *)pu8)->len) = param_pktlen;
    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
    (((pay_hdr_t *)pu8)->stp_n) = stp_n;

    r = write(fd, buffer, packet_size);
    if (r != packet_size) exit(-1);

    printf("(%d)(%d)\n",seq,param_pktlen);
    printf("(%ld)\n",stp_n);
    printf("number of packets sent = %d\r", i);
    fflush(stdout);
    seq++;
    usleep(param_ndelay);
    printf("\n");
  }
}
