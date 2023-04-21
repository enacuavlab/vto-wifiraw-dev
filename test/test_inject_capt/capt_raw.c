#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <unistd.h>
#include <fcntl.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint32_t port = 5;

  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };
  ((struct sock_filter *)&bpf_bytecode[1])->k = port;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};

  uint8_t flags;
  uint16_t fd = 0, protocol = htons(ETH_P_ALL); 
  if (-1 == (fd=socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd, F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd, F_SETFL, flags | O_NONBLOCK))) exit(-1);

  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);

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

  char drain[1];
  while (recv(fd, drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);

  struct timespec curr,start;
  uint64_t inline_stp_n, curr_n, total_nb=0, total_size=0;
  float delta_m, total_m;
  uint16_t n, u16HeaderLen,inline_len,inline_seq;
  uint8_t *pu8,payload;

  uint8_t packetBuffer[PKT_SIZE];
  for(;;) { 
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    n = select(fd+1, &readset, NULL, NULL, NULL);
    if(n == 0) exit(-1);
    if(FD_ISSET(fd, &readset)) {  // Less CPU consumption than pcap_loop()
  
      if ( n == 1 ) {
        ssize_t bytes = read( fd, packetBuffer, sizeof(packetBuffer) );
  
        if (bytes >=0 ) {
  
          clock_gettime( CLOCK_MONOTONIC, &curr);
  
	  pu8 = packetBuffer; 

          u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
          payload = u16HeaderLen + sizeof(ieee_hdr_data);
    
          pu8 += payload;
          inline_seq = (((pay_hdr_t *)pu8)->seq);
          inline_len = (((pay_hdr_t *)pu8)->len);
          inline_stp_n = (((pay_hdr_t *)pu8)->stp_n);
  
          if (inline_seq == 0) {
            start.tv_sec = curr.tv_sec;
            start.tv_nsec = curr.tv_nsec;
          }
  
          curr_n = (curr.tv_nsec + (curr.tv_sec * 1000000000L));
          delta_m = (float)(curr_n - inline_stp_n) / 1000000;
  
          printf("seq(%d) len(%d)\n",inline_seq,inline_len);
          printf("stamp(%ld)\n",inline_stp_n);
          printf("delta mil(%.03f)\n",delta_m);
  
          if (inline_seq != 0) {
            total_m = (float)(curr_n - (start.tv_nsec + (start.tv_sec * 1000000000L))) / 1000000 ;
            printf("total mil[%.03f]\n",total_m);
            printf("Mbitps(%.02f)\n",8 * total_size / (1000*total_m));
          }
  
          printf("total nb(%ld)\n",total_nb);
  
          total_nb++;
          total_size+=inline_len;
          printf("----------------------------------------\n");
        }
      }
    }
  }
}
