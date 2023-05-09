#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <unistd.h>
#include <fcntl.h>

#include "inject_capt.h"

/*
 *
sudo ./rx_raw 127.0.0.1:6000 $node

gst-launch-1.0 -v udpsrc port=6000 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink

*/

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t  param_portid = 5;

  setpriority(PRIO_PROCESS, 0, -10);

  char node[20],addr_str[20];
  uint16_t port=0;
  if ((argc==1)||(argc>3)) exit(-1);
  if (argc>1) strcpy(node,argv[argc - 1]);
  if (argc==3) { char *ch=strtok(argv[1],":"); strcpy(addr_str,&ch[0]); port=atoi(strtok(NULL,":")); }

  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };

  ((struct sock_filter *)&bpf_bytecode[1])->k = param_portid;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};

  uint8_t flags;
  uint16_t fd_raw = 0, protocol = htons(ETH_P_ALL); 
  if (-1 == (fd_raw = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd_raw, F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd_raw, F_SETFL, flags | O_NONBLOCK))) exit(-1);

  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(fd_raw, SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, node, sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd_raw, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(fd_raw, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  char drain[1];
  while (recv(fd_raw, drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(fd_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);


  uint16_t fd_out = STDOUT_FILENO;
  struct sockaddr_in addr;
  if (port!=0) {
    if (-1 == (fd_out=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(addr_str);
  }

  struct timespec curr;
  uint64_t stp_n;
  uint32_t dataLen;
  uint16_t offset,u16HeaderLen,len,seq,n,r;
  uint8_t *pu8, *ppay;
  pay_hdr_t *phead;

  uint32_t crc, crc_rx;
  build_crc32_table();

  uint8_t packetBuffer[PKT_SIZE_1];
  for(;;) { 
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd_raw, &readset);
    n = select(fd_raw+1, &readset, NULL, NULL, NULL);
    if(n == 0) exit(-1);
    if(FD_ISSET(fd_raw, &readset)) {  // Less CPU consumption than pcap_loop()
  
      if ( n == 1 ) {
        ssize_t bytes = read( fd_raw, packetBuffer, sizeof(packetBuffer) );
  
        if (bytes >=0 ) {

          clock_gettime( CLOCK_MONOTONIC, &curr);
  
	  pu8 = packetBuffer; 

          u16HeaderLen = (pu8[2] + (pu8[3] << 8)); // variable radiotap header size
          offset = u16HeaderLen + sizeof(ieee_hdr_data);

	  phead = (pay_hdr_t *)(pu8 + offset);
          seq = phead->seq;
          len = phead->len;
          stp_n = phead->stp_n;
/*
	  dataLen = sizeof(pay_hdr_t) + len;
          const uint8_t *s = &packetBuffer[offset]; // Do not include radiotap header
	  printf("(%x)(%x)\n",s[0],s[1]);
          crc=0xFFFFFFFF;
          for(uint32_t i=0;i<dataLen;i++) {
            uint8_t ch=s[i];
            uint32_t t=(ch^crc)&0xFF;
            crc=(crc>>8)^crc32_table[t];
          }

          memcpy(&crc_rx, &packetBuffer[(u16HeaderLen + dataLen)], sizeof(crc_rx));

          printf("(%d)(%lu)(%lu)\n",seq,(unsigned long)(crc_rx),(unsigned long)(~crc));
*/

	  ppay = (pu8 + offset + sizeof(pay_hdr_t));
	  if (port!=0) r = sendto(fd_out,ppay,len,0,(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	  else write(fd_out, ppay, len);
        }
      }
    }
  }
}
