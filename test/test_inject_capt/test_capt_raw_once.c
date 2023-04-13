#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/filter.h>

#include "test_inject.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t port = 5;

  // match on frametype and port
  // tcpdump 'ether[0x00:2] = 0x8800 and ether[0x04:2] = 0xff05' -dd
/*
  struct sock_filter bpf_bytecode[] = { 
    { 0x28, 0, 0, 0x00000000 },
    { 0x15, 0, 3, 0x00008800 },
    { 0x28, 0, 0, 0x00000004 },
    { 0x15, 0, 1, 0x0000ff05 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
*/
  // sudo tcpdump ether dst host ff:05:ff:ff:ff:ff -dd
  struct sock_filter bpf_bytecode[] = { 
    { 0x20, 0, 0, 0x00000002 },
    { 0x15, 0, 3, 0xffffffff },
    { 0x28, 0, 0, 0x00000000 },
    { 0x15, 0, 1, 0x0000ff05 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
  };

  uint16_t fd = 0;
  if (-1 == (fd=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};
//  if (-1 == setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(fd, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  struct timespec curr;
  uint64_t stp_n, curr_n; 
  float delta_m;
  uint16_t n, u16HeaderLen,len,seq;
  uint8_t *pu8,payload;
  
  fd_set readset;
  FD_ZERO(&readset);
  FD_SET(fd, &readset);
  n = select(fd+1, &readset, NULL, NULL, NULL);
  if(n == 0) exit(-1);
  if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()

    if ( n == 1 ) {
      uint8_t packetBuffer[4096];
      ssize_t bytes = read( fd, packetBuffer, sizeof(packetBuffer) );

      if (bytes >=0 ) {

        clock_gettime( CLOCK_MONOTONIC, &curr);
 
        pu8 = packetBuffer;

        u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
        payload = u16HeaderLen + sizeof(wifi_hdr) + sizeof(llc_hdr);
  
        pu8 += payload;
        seq = (((pay_hdr_t *)pu8)->seq); 
        len = (((pay_hdr_t *)pu8)->len); 
        stp_n = (((pay_hdr_t *)pu8)->stp_n);
  
        curr_n = (curr.tv_nsec + (curr.tv_sec * 1000000000L));
        delta_m = (float)(curr_n - stp_n) / 1000000;
        
        printf("(%d)(%d)\n",seq,len);
        printf("(%ld)\n",stp_n);
        printf("(%.03f)\n",delta_m);
      }
    }
  }
}
