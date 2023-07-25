/*
gcc ./test_rcv.c -o test_rcv
gcc ./test_rcv.c -o test_rcv -DRAW
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdbool.h>

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
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
static uint8_t ieeehdr[] = {
  0x08, 0x01,                         // Frame Control : Data frame from STA to DS
  0x00, 0x00,                         // Duration
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Receiver MAC 
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Transmitter MAC
  0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Destination MAC
  0x10, 0x86                          // Sequence control
};
uint32_t crc32_table[256];
void build_crc32_table(void) {
  for(uint32_t i=0;i<256;i++) {
    uint32_t ch=i;
    uint32_t crc=0;
    for(uint32_t j=0;j<8;j++) {
      uint32_t b=(ch^crc)&1;
      crc>>=1;
      if(b) crc=crc^0xEDB88320;
      ch>>=1;
    }
    crc32_table[i]=crc;
  }
}
// ONLINE8SIZE on RAW receveiver should be large enought to retrieve variable size radiotap header
#define RADIOTAP_HEADER_MAX_SIZE 30
#define ONLINE_SIZE ( RADIOTAP_HEADER_MAX_SIZE + sizeof(ieeehdr) + sizeof(payhdr_t) + sizeof(subpayhdr_t) + MTU )
#define DRONEID 5
#define ADDR_LOCAL "127.0.0.1"
#else  
#define ONLINE_SIZE ( sizeof(payhdr_t) + sizeof(subpayhdr_t) + MTU )
#define ADDR_REMOTE_GROUND "192.168.3.1"
#endif // RAW


/*****************************************************************************/
int main(int argc, char *argv[]) {

  struct sockaddr_in addr_in,addr_out;
  uint16_t fd_in,fd_out;

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

#ifdef RAW                 
  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };
  ((struct sock_filter *)&bpf_bytecode[1])->k = DRONEID;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};
  uint8_t flags;
  uint16_t protocol = htons(ETH_P_ALL); 
  if (-1 == (fd_in = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd_in, F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd_in, F_SETFL, flags | O_NONBLOCK))) exit(-1);
  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(fd_in, SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
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
  build_crc32_table();
  uint16_t datalen, radiotapvar,pos;
  int8_t antdbm;
  uint32_t crc, crc_rx;
  uint32_t fails = 0;
#else
  if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(5100);
  addr_in.sin_addr.s_addr = inet_addr(ADDR_REMOTE_GROUND); 
  if (-1 == bind(fd_in, (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);
#endif // RAW
  FD_SET(fd_in, &(readset_ref));

  if (-1 == (fd_out=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out.sin_family = AF_INET;
  addr_out.sin_port = htons(5700);
  addr_out.sin_addr.s_addr = inet_addr(ADDR_LOCAL);

  struct timeval timeout;
  uint8_t onlinebuff[ONLINE_SIZE],*ptr;
  bool crcok = false;
  ssize_t len;
  uint8_t id;
  uint16_t ret,seq;
  uint64_t stp_n;
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(fd_in+1, &readset, NULL, NULL, &timeout);
    if (ret == 1) {
      len = read(fd_in, onlinebuff, ONLINE_SIZE);
      printf("(%ld)\n",len);

#ifdef RAW	

      radiotapvar = (onlinebuff[2] + (onlinebuff[3] << 8)); // get variable radiotap header size
      pos = radiotapvar + sizeof(ieeehdr);
      antdbm = onlinebuff[31];
      datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + ((payhdr_t *)(onlinebuff + pos))->len;
      const uint8_t *s = &onlinebuff[radiotapvar];  // compute CRC32 after radiotap header
      crc=0xFFFFFFFF;
      for(uint32_t i=0;i<datalen;i++) {
        uint8_t ch=s[i];
        uint32_t t=(ch^crc)&0xFF;
        crc=(crc>>8)^crc32_table[t];
      }
      memcpy(&crc_rx, &onlinebuff[len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
      if (~crc != crc_rx) {fails ++;crcok=false;}
      else crcok = true;
      ptr=onlinebuff+pos+sizeof(payhdr_t);
#else
      ptr=onlinebuff;
      crcok = true;
#endif // RAW

      if (crcok) {      
        seq = ((payhdr_t *)ptr)->seq;
        len = ((payhdr_t *)ptr)->len;
        stp_n = ((payhdr_t *)ptr)->stp_n;
        ptr+=sizeof(payhdr_t);
        id = ((subpayhdr_t *)ptr)->id;
        len = ((subpayhdr_t *)ptr)->len;
        ptr+=sizeof(subpayhdr_t);
        len = sendto(fd_out, ptr, len, 0, (struct sockaddr *)&(addr_out), sizeof(struct sockaddr));
      }
    }
  }
}
