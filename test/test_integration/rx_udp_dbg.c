#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "inject_capt.h"

#define UDP_SIZE 65507

/*
sudo ./rx_udp_dbg 127.0.0.1:6000 $node
*/
/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t  param_portid = 5;

  setpriority(PRIO_PROCESS, 0, -10);

  char node[20],addr_str[20];
  uint16_t port_out=0;
  if ((argc==1)||(argc>3)) exit(-1);
  if (argc>1) strcpy(node,argv[argc - 1]);
  if (argc==3) { char *ch=strtok(argv[1],":"); strcpy(addr_str,&ch[0]); port_out=atoi(strtok(NULL,":")); }

  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };

  ((struct sock_filter *)&bpf_bytecode[1])->k = param_portid;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};

  uint8_t flags;
  uint16_t fd_in = 0, protocol = htons(ETH_P_ALL); 
  if (-1 == (fd_in = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd_in, F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd_in, F_SETFL, flags | O_NONBLOCK))) exit(-1);

  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(fd_in, SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, node, sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd_in, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(fd_in, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  char drain[1];
  while (recv(fd_in, drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(fd_in, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);

  uint16_t fd_out;
  struct sockaddr_in addr_out;
  if (-1 == (fd_out=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out.sin_family = AF_INET;
  addr_out.sin_port = htons(port_out);
  addr_out.sin_addr.s_addr = inet_addr(addr_str);

  ssize_t len_in, len_out;
  uint16_t len = 0, ret;
  uint8_t udp_in[DATA_SIZE];
  uint8_t udp_out[UDP_SIZE];

  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd_in, &readset);
    ret = select(fd_in + 1, &readset, NULL, NULL, NULL);
    if(FD_ISSET(fd_in, &readset)) {  
      if ( ret == 1 ) {
        len_in = read(fd_in, udp_in, DATA_SIZE);
        printf("read(%ld)\n",len_in);
        if (len_in > 0) {
          memcpy(udp_out + len , udp_in, len_in);
          len += len_in;
          if (len_in < DATA_SIZE) {
            len_out = sendto(fd_out, udp_out, len, 0, (struct sockaddr *)&addr_out, sizeof(struct sockaddr));
            printf("sendto(%ld)\n",len_out);
    	    len = 0;
          }
        }
      }
    }
  }
}
