/*
gcc ./test_snd.c -i test_snd
gcc ./test_snd.c -i test_snd -DRAW
*/


#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define MTU 1400
#define ADDR_LOCAL "127.0.0.1"

typedef struct {
  uint16_t seq;
  uint16_t len;  // len for the full payload not including (pay_hdr_t)
  uint64_t stp_n;
} __attribute__((packed)) payhdr_t;

typedef struct {
  uint8_t id;
  uint16_t len; // len for the subpayload not including (sub_pay_hdr_t)
} __attribute__((packed)) subpayhdr_t;

#ifdef RAW
#include <string.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
static uint8_t radiotaphdr[] =  {
  0x00, 0x00,             // radiotap version
  0x0d, 0x00,             // radiotap header length
  0x00, 0x80, 0x08, 0x00, // radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
  0x08, 0x00,             // RADIOTAP_F_TX_NOACK
  0x07, 0x00, 0x04,       // MCS flags (0x07), 0x0, rate index (0x05)
};
static uint8_t ieeehdr[] = {
  0x08, 0x01,                         // Frame Control : Data frame from STA to DS
  0x00, 0x00,                         // Duration
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Receiver MAC 
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Transmitter MAC
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Destination MAC
  0x10, 0x86                          // Sequence control
};
#define ONLINE_SIZE ( sizeof(radiotaphdr) + sizeof(ieeehdr) + sizeof(payhdr_t) + sizeof(subpayhdr_t) + MTU )
#define DRONEID	5
#else
#define ONLINE_SIZE ( sizeof(payhdr_t) + sizeof(subpayhdr_t) + MTU )
#endif // RAW

/*****************************************************************************/
int main(int argc, char *argv[]) {

  struct sockaddr_in addr_in,addr_out;
  uint16_t fd_in,fd_out;
  int8_t offset;

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(5600);
  addr_in.sin_addr.s_addr = inet_addr(ADDR_LOCAL); 
  if (-1 == bind(fd_in, (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);
  FD_SET(fd_in, &(readset_ref));

#ifdef RAW
  uint8_t flags;
  uint16_t protocol = htons(ETH_P_ALL); 
  if (-1 == (fd_out=socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags=fcntl(fd_out, F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd_out, F_SETFL, flags | O_NONBLOCK))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd_out, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );          // Bind is mandatory to send !?
  if((bind( fd_out, (struct sockaddr *)&sll, sizeof(sll))) == -1) exit(-1);
  offset=(sizeof(radiotaphdr)+sizeof(ieeehdr));
  ieeehdr[9] = DRONEID;
#else
  if (-1 == (fd_out=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out.sin_family = AF_INET;
  addr_out.sin_port = htons(5100);
  addr_out.sin_addr.s_addr = inet_addr(ADDR_REMOTE_GROUND);
  offset=0;
#endif // RAW

  struct timespec stp;
  struct timeval timeout;
  uint8_t onlinebuff[ONLINE_SIZE];
  uint8_t *ptr0=(onlinebuff+offset+sizeof(payhdr_t)+sizeof(subpayhdr_t));
  uint8_t *ptr=ptr0;
  ssize_t len;
  uint16_t ret,seq=0;;
  uint64_t stp_n,stp_prev_n=0,inter_n=0,lentot=0,timetot_n=0;
  float byterate=0.0,minrate=0.0,maxrate=0.0;
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(fd_in+1, &readset, NULL, NULL, &timeout);
    if (ret == 1) {
      ptr = ptr0;
      len = read(fd_in, ptr, MTU);

      clock_gettime( CLOCK_REALTIME, &stp);
      stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

      ptr-=sizeof(subpayhdr_t);
      ((subpayhdr_t *)ptr)->id = 1;
      ((subpayhdr_t *)ptr)->len = len;

      ptr-=sizeof(payhdr_t);
      ((payhdr_t *)ptr)->seq = seq;
      ((payhdr_t *)ptr)->len = len + sizeof(subpayhdr_t);
      ((payhdr_t *)ptr)->stp_n = stp_n;

#ifdef RAW
      memcpy(onlinebuff,radiotaphdr,sizeof(radiotaphdr));
      memcpy(onlinebuff+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
      write(fd_out, onlinebuff, sizeof(radiotaphdr)+sizeof(ieeehdr)+sizeof(payhdr_t)+sizeof(subpayhdr_t)+len);
      // 800 ns sleep delay is within the inputs delays
#else
      sendto(fd_out, onlinebuff, sizeof(payhdr_t)+sizeof(subpayhdr_t)+len, 0, (struct sockaddr *)&(addr_out), sizeof(struct sockaddr));
#endif // RAW

      if (stp_prev_n != 0) inter_n = stp_n - stp_prev_n;
      stp_prev_n = stp_n;
      if (inter_n != 0) byterate = (1000.0 * (float)len / ((float)inter_n));
      if (minrate == 0.0) minrate=byterate;
      if (maxrate == 0.0) maxrate=byterate;
      if (byterate < minrate) minrate = byterate;
      if (byterate > maxrate) maxrate = byterate;
      lentot += len;
      timetot_n += inter_n;
      printf("(%d)(%ld)(%ld)(%f)(%f)\n",seq,len,stp_n,(float)(inter_n / 1000000.0),byterate);
      printf("(%f)(%f)(%f)\n",(1000.0 * (float)lentot / ((float)timetot_n)),minrate,maxrate);

      seq++;
    }
  }
}
