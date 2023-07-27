#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdbool.h>
#include <time.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>


#define FD_NB 2
#define ONLINE_MTU 1400
#define TUN_MTU 1400
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
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
static uint8_t radiotaphdr[] =  {
  0x00, 0x00,             // radiotap version
  0x0d, 0x00,             // radiotap header length
  0x00, 0x80, 0x08, 0x00, // radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
  0x08, 0x00,             // RADIOTAP_F_TX_NOACK
  0x07, 0x00, 0x02,       // MCS flags (0x07), 0x0, rate index (0x05)
};
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
#define RADIOTAP_HEADER_MAX_SIZE 50
#define ONLINE_SIZE ( RADIOTAP_HEADER_MAX_SIZE + sizeof(ieeehdr) + sizeof(payhdr_t) + sizeof(subpayhdr_t) + ONLINE_MTU )
#define DRONEID 5
#define ADDR_LOCAL "127.0.0.1"
#else  
#define ONLINE_SIZE ( sizeof(payhdr_t) + sizeof(subpayhdr_t) + ONLINE_MTU )
#endif // RAW


/*****************************************************************************/
int main(int argc, char *argv[]) {

  struct ifreq ifr;
  uint16_t dev,maxfd,fd[FD_NB];

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  dev=0;
  int8_t offsetraw;
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
  if (-1 == (fd[dev] = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(fd[dev], F_GETFL))) exit(-1);
  if (-1 == (fcntl(fd[dev], F_SETFL, flags | O_NONBLOCK))) exit(-1);
  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(fd[dev], SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( fd[dev], SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(fd[dev], (struct sockaddr *)&sll, sizeof(sll))) exit(-1);
  char drain[1];
  while (recv(fd[dev], drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(fd[dev], SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);
  build_crc32_table();
  uint16_t datalen, radiotapvar;
  int8_t antdbm,offset;
  uint32_t crc, crc_rx;
  offsetraw=sizeof(radiotaphdr)+sizeof(ieeehdr);
  ieeehdr[9] = DRONEID;
#else
  offsetraw=0;
  struct sockaddr_in addr_in[FD_NB],addr_out[FD_NB];
#if ROLE
  addr_in[dev].sin_addr.s_addr = inet_addr(ADDR_REMOTE_BOARD); 
  addr_out[dev].sin_addr.s_addr = inet_addr(ADDR_REMOTE_GROUND); 
#else
  addr_in[dev].sin_addr.s_addr = inet_addr(ADDR_REMOTE_GROUND); 
  addr_out[dev].sin_addr.s_addr = inet_addr(ADDR_REMOTE_BOARD); 
#endif // ROLE
  if (-1 == (fd[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_in[dev].sin_family = AF_INET;
  addr_in[dev].sin_port = htons(5100);
  if (-1 == bind(fd[dev], (struct sockaddr *)&addr_in[dev], sizeof(addr_in))) exit(-1);
  addr_out[dev].sin_family = AF_INET;
  addr_out[dev].sin_port = htons(5100);
#endif // RAW
  FD_SET(fd[dev], &(readset_ref));
  maxfd=fd[dev];


  dev=1;   // Tunnel (one bidirectional link)
  memset(&ifr, 0, sizeof(struct ifreq));
  struct sockaddr_in addr, dstaddr;
  uint16_t fd_tun_udp;
  char *addr_str_tunnel_board = "10.0.1.2";
  char *addr_str_tunnel_ground = "10.0.1.1";
#if ROLE 
  strcpy(ifr.ifr_name,"airtun");
  addr.sin_addr.s_addr = inet_addr(addr_str_tunnel_board);
  dstaddr.sin_addr.s_addr = inet_addr(addr_str_tunnel_ground);
#else
  strcpy(ifr.ifr_name, "grdtun");
  addr.sin_addr.s_addr = inet_addr(addr_str_tunnel_ground);
  dstaddr.sin_addr.s_addr = inet_addr(addr_str_tunnel_board);
#endif // ROLE
  if (0 > (fd[dev]=open("/dev/net/tun",O_RDWR))) exit(-1);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (ioctl( fd[dev], TUNSETIFF, &ifr ) < 0 ) exit(-1);
  if (-1 == (fd_tun_udp=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr.sin_family = AF_INET;
  memcpy(&ifr.ifr_addr,&addr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFADDR, &ifr ) < 0 ) exit(-1);
  addr.sin_addr.s_addr = inet_addr( "255.255.255.0");
  memcpy(&ifr.ifr_addr,&addr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFNETMASK, &ifr ) < 0 ) exit(-1);
  dstaddr.sin_family = AF_INET;
  memcpy(&ifr.ifr_addr,&dstaddr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFDSTADDR, &ifr ) < 0 ) exit(-1);
  ifr.ifr_mtu = TUN_MTU;
  if (ioctl( fd_tun_udp, SIOCSIFMTU, &ifr ) < 0 ) exit(-1);
  ifr.ifr_flags = IFF_UP ;
  if (ioctl( fd_tun_udp, SIOCSIFFLAGS, &ifr ) < 0 ) exit(-1);
  FD_SET(fd[dev], &(readset_ref));
  if (fd[dev]>maxfd) maxfd=fd[dev];


  struct timespec stp;
  struct timeval timeout;
  uint8_t onlinebuff[ONLINE_SIZE],*ptr;
  bool crcok = false;
  ssize_t len;
  uint8_t id;
  uint16_t ret,seq,seq_prev,seq_out=0;
  uint32_t fails=0,drops=0;
  uint64_t stp_n;
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(maxfd + 1, &readset, NULL, NULL, &timeout);
    if (ret >0) {
      for (int cpt = 0; cpt < (maxfd+1); cpt++) {
        if(FD_ISSET(fd[cpt], &readset)) {
          if (cpt == 0) {
            len = read(fd[0], onlinebuff, ONLINE_SIZE);
#ifdef RAW	
            radiotapvar = (onlinebuff[2] + (onlinebuff[3] << 8)); // get variable radiotap header size
            offset = radiotapvar + sizeof(ieeehdr);
            antdbm = onlinebuff[31];
            datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + ((payhdr_t *)(onlinebuff + offset))->len;
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
            ptr=onlinebuff+offset;
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
              write(fd[1], ptr, len);
      
              if ((seq>1) && (seq_prev != seq-1)) drops ++;
              seq_prev = seq;
            }
	  } else {

            ptr = onlinebuff+offsetraw;

            len = read(fd[1], ptr+sizeof(payhdr_t)+sizeof(subpayhdr_t), ONLINE_SIZE-offsetraw-+sizeof(payhdr_t)-sizeof(subpayhdr_t));
	    clock_gettime( CLOCK_MONOTONIC, &stp);
            stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

            (((payhdr_t *)ptr)->seq) = seq_out;
            (((payhdr_t *)ptr)->len) = len + sizeof(subpayhdr_t);;
            (((payhdr_t *)ptr)->stp_n) = stp_n;

            ptr += sizeof(payhdr_t);
            (((subpayhdr_t *)ptr)->id) = 1;
            (((subpayhdr_t *)ptr)->len) = len;
#ifdef RAW                 
            memcpy(onlinebuff,radiotaphdr,sizeof(radiotaphdr));
            memcpy(onlinebuff+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
	    len = write(fd[0],onlinebuff,offset+sizeof(payhdr_t)+sizeof(subpayhdr_t)+len);
#else
	    len = sendto(fd[0],onlinebuff+offsetraw,sizeof(payhdr_t)+sizeof(subpayhdr_t)+len,0,(struct sockaddr *)&(addr_out[0]), sizeof(struct sockaddr));
#endif // RAW
	    seq_out++;
	  }
	}
      }
    }
  }
}
