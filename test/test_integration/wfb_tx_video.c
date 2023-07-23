#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h> 
#include <termios.h>
#include <fcntl.h>
#include <string.h>
#include <netpacket/packet.h>
#include <stdbool.h>

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

#define UDP_SIZE 65507
#define PAYLOAD_SIZE 1500
#define FD_NB 3

typedef struct {
  uint16_t seq;
  uint16_t len;  // len for the full payload not including (pay_hdr_t)
  uint64_t stp_n;
} __attribute__((packed)) payhdr_t;
payhdr_t *payhdr_p;

typedef struct {
  uint8_t id;
  uint16_t len; // len for the subpayload not including (sub_pay_hdr_t)
} __attribute__((packed)) subpayhdr_t;

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t udp[UDP_SIZE], *ptr,*ptrhd;
  uint16_t fd[FD_NB],fdsize[FD_NB],dev,maxdev,maxfd=0,ret,seqout=1;
  int8_t offsetraw;
  int32_t lensum=0;
  struct sockaddr_in addr_in[FD_NB];
  struct ifreq ifr;
  struct sockaddr_ll sll;
  ssize_t len;
  uint64_t stp_n;
  struct timespec stp;
  struct timeval timeout;

  char *addr_str_local = "127.0.0.1";

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  int8_t droneid = 5;
  uint8_t flags;
  uint16_t protocol = htons(ETH_P_ALL); 

  dev=0; maxdev=dev; 
  if (-1 == (fd[dev] = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd[dev], F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd[dev], F_SETFL, flags | O_NONBLOCK))) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd[dev], SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );          // Bind is mandatory to send !?
  if((bind( fd[dev], (struct sockaddr *)&sll, sizeof(sll))) == -1) exit(-1);
  offsetraw=(sizeof(radiotaphdr)+sizeof(ieeehdr));

  dev=2; maxdev=dev;  // Video (one directional link)
  if (-1 == (fd[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_in[dev].sin_family = AF_INET;
  addr_in[dev].sin_port = htons(5600);
  addr_in[dev].sin_addr.s_addr = inet_addr(addr_str_local);
  if (-1 == bind(fd[dev], (struct sockaddr *)&addr_in[dev], sizeof(addr_in[dev]))) exit(-1);
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  fdsize[dev]=1500;
  maxfd=fd[dev];

  ptr = udp+sizeof(payhdr_t)+offsetraw;
  lensum=0;

  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(maxfd + 1, &readset, NULL, NULL, &timeout);

    if (ret >0) {
      for (int cpt = 0; cpt < (maxdev+1); cpt++) {
        if(FD_ISSET(fd[cpt], &readset)) {
          len = read(fd[cpt], ptr+sizeof(subpayhdr_t), fdsize[cpt]);
	  printf("IN %ld\n",len);
          ((subpayhdr_t *)ptr)->id=cpt;
          ((subpayhdr_t *)ptr)->len=len;
          lensum = (len+sizeof(subpayhdr_t));
        }
      }
    }           
    if (lensum>0) {
      clock_gettime( CLOCK_REALTIME, &stp);
      stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
      ptrhd = udp + offsetraw;
      ((payhdr_t *)ptrhd)->seq = seqout;
      ((payhdr_t *)ptrhd)->len = lensum;
      ((payhdr_t *)ptrhd)->stp_n = stp_n;
      memcpy(udp,radiotaphdr,sizeof(radiotaphdr));
      ieeehdr[9] = droneid;
      memcpy(udp+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
      len = write(fd[0], udp, lensum + sizeof(payhdr_t) + offsetraw);

      printf("OUT %ld\n",len);

      lensum=0;
      seqout++;
    }
  }
}
