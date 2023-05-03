#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint16_t param_pktnb  = 2000;
  uint16_t param_pktlen = 1441;
  uint16_t param_ndelay = 800;
  uint8_t param_bitrate = 0x5; // 0x0, 0x3  -> 0x05
  uint8_t param_portid = 5;

  printf("%d\n",DATA_SIZE);
  if (param_pktlen >  DATA_SIZE) exit(-1);

  setpriority(PRIO_PROCESS, 0, -10);

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
  if((bind(fd, (struct sockaddr *)&sll, sizeof(sll))) == -1) exit(-1);

  uint8_t buffer[PKT_SIZE_0], *ieee_hdr = ieee_hdr_data, *radiotap_hdr = uint8_taRadiotapHeader;
  uint8_t *ppay, *pu8 = buffer;
  pay_hdr_t *phead;

  memset(buffer, 0, sizeof (buffer));
  radiotap_hdr[27] = param_bitrate;
  memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  ieee_hdr[9] = param_portid; // Set in receiver address
  memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));

  struct timespec stp;
  uint64_t stp_n;
  uint16_t r,seq=1,packet_size = PKT_SIZE_0;
  uint16_t offset0 = sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data);
  uint16_t offset1 = offset0 + sizeof(pay_hdr_t);

  for(int i = 1; i <= param_pktnb; i++) {

    ppay = (pu8 + offset1);

    memset((char *)ppay,0,13);
    if (i == 1) strcpy((char *)ppay,"firstpkt-beg");
    else if (i == param_pktnb) strcpy((char *)ppay,"lastpkt-beg");

    phead = (pay_hdr_t *)(pu8 + offset0);
    phead->seq = seq;
    phead->len = param_pktlen;

    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

    phead->stp_n = stp_n;

    r = write(fd, buffer, packet_size);
    if (r != packet_size) exit(-1);

    printf("(%d)(%d)\n",seq,param_pktlen);
    printf("(%ld)\n",stp_n);
    printf("number of packets sent = %d\r", i);
    printf("\n");
    fflush(stdout);

    seq++;
    usleep(param_ndelay);
  }
}
