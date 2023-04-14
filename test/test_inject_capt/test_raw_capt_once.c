#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/filter.h>

#include "capt_inject.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint32_t port = 6;

  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x00000028 }, // Ldb = 0x30, load one byte at position 0x28 (offset = 40) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };
  ((struct sock_filter *)&bpf_bytecode[1])->k = port;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};

  uint16_t fd = 0, protocol = htons(ETH_P_ALL); 
  if (-1 == (fd=socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
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

	for (int i=0;i<10;i++) printf("%x ",packetBuffer[i]);
      }
    }
  }
}
