#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


#include "inject_capt.h"

#define UDP_SIZE 65507

/*
sudo ./tx_udp_dbg 127.0.0.1:5000 $node
*/
/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char node[20],addr_str[20];
  uint16_t port_in=0;
  if ((argc==1)||(argc>3)) exit(-1);
  if (argc>1) strcpy(node,argv[argc - 1]);
  if (argc==3) { char *ch=strtok(argv[1],":"); strcpy(addr_str,&ch[0]); port_in=atoi(strtok(NULL,":")); }
  uint8_t  param_portid = 5;

  uint16_t fd_in;
  if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  struct sockaddr_in addr_in;
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(port_in);
  addr_in.sin_addr.s_addr = inet_addr(addr_str);
  if (-1 == bind(fd_in, (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);

  uint16_t fd_out = 0;
  if (-1 == (fd_out=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, node, sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( fd_out, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(fd_out, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  uint16_t offset0 = sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data);
  uint16_t offset1 = offset0 + sizeof(pay_hdr_t);

  ssize_t len_in;
  uint16_t len = 0, offset = 0, seq = 1, len_tag;
  uint8_t udp_in[UDP_SIZE];

  uint64_t stp_n;
  struct timespec stp;
  pay_hdr_t *phead;

  for(;;) {
    len_in = read(fd_in, udp_in + offset1, UDP_SIZE - offset1);
    printf("(%ld)\n",len_in);
    offset = 0;
    while (len_in > 0) {
      if (len_in > DATA_SIZE) { len = DATA_SIZE; len_tag = len; }
      else { len = len_in; len_tag = len; (len_tag |= 1UL << 15); } // Set signed bit of unsigned length to signal  sequence end
    
      printf("(%d)(%d)\n",len,len_tag);

      memcpy( udp_in + offset, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
      ieee_hdr_data[9] = param_portid;
      memcpy( udp_in + offset + sizeof(uint8_taRadiotapHeader), ieee_hdr_data, sizeof(ieee_hdr_data));
      phead = (pay_hdr_t *)(udp_in + offset + offset0);
      phead->seq = seq;
      phead->len = len_tag;
      clock_gettime( CLOCK_MONOTONIC, &stp);
      stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
      phead->stp_n = stp_n;
         
      write(fd_out, udp_in + offset, len + offset1);

      offset += len;
      len_in -= len;

      usleep(800);
    }
    if (seq == 65535)  seq = 1;  else seq++;
  }
}
