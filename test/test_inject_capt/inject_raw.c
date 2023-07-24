#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint16_t param_pktnb  = 2000;
  uint16_t param_pktlen = 1400;
  uint16_t param_ndelay = 800;
  uint8_t param_portid = 5;

#ifdef LEGACY
  uint8_t param_bitrate = 0x30; // (x500 Mb/s) range [0x02,0x04,0x06,0x0c,0x18,0x30,0x40,0x60,0x6c]
  uint8_t offset = 8;
#else 
  uint8_t param_bitrate = 0x02; // MCS index range [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07]
  uint8_t offset = 12;
#endif

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
  radiotap_hdr[offset] = param_bitrate;
  memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  ieee_hdr[9] = param_portid; // Set in receiver address
  memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));

  struct timespec stp;
  uint64_t stp_n,stp_prev_n=0,inter_n=0,lentot=0,timetot_n=0;
  uint16_t r,seq=1,packet_size = PKT_SIZE_0;
  uint16_t offset0 = sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data);
  uint16_t offset1 = offset0 + sizeof(pay_hdr_t);
  float byterate=0.0,minrate=0.0,maxrate=0.0;

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
    if (stp_prev_n != 0) inter_n = stp_n - stp_prev_n;
    stp_prev_n = stp_n;

    phead->stp_n = stp_n;

    lentot += param_pktlen;
    timetot_n += inter_n;

    r = write(fd, buffer, packet_size);
    if (r != packet_size) exit(-1);

    if (inter_n != 0) {
      byterate = (1000.0 * (float)param_pktlen / ((float)inter_n));
    }
    if (minrate == 0.0) minrate=byterate;
    if (maxrate == 0.0) maxrate=byterate;
    if (byterate < minrate) minrate = byterate;
    if (byterate > maxrate) maxrate = byterate;

    printf("(%d)(%d)(%ld)(%f)(%f)\n",seq,param_pktlen,stp_n,(float)(inter_n / 1000000.0),byterate);
    printf("(%f)(%f)(%f)\n",(1000.0 * (float)lentot / ((float)timetot_n)),minrate,maxrate);

    seq++;
    usleep(param_ndelay);
  }
}
