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

#ifdef RAW
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
#endif 

#define TUN_MTU 1400
#define UDP_SIZE 65507
#define PAYLOAD_SIZE 1500
#define FD_NB 4

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

#if ROLE == 0
  uint16_t fd_out[FD_NB];
#endif // ROLE==0
#if !defined(RAW) || (ROLE ==0)
  struct sockaddr_in addr_out[FD_NB];
#endif // !defined(RAW) || (ROLE ==0)
       
  uint8_t udp[UDP_SIZE], *ptr,*curr_p,*nextcurr_p;
  uint16_t fd[FD_NB],fd_tun_udp,id,dev,maxdev,maxfd=0,ret,seqout=1,seq,seqprev,cpt,curr_cpt,cpttmp,subpaynb;
  uint32_t totdrops=0;
  bool crcok = false;
  int8_t offsetraw;
  int32_t lensum=0,lenpay,nextlenpay,lentmp,subpaylen[FD_NB];
  struct sockaddr_in addr, dstaddr,addr_in[FD_NB];
  struct ifreq ifr;
  ssize_t len;
  uint64_t stp_n;
  struct timespec stp;
  struct timeval timeout;
  char *addr_str_local = "127.0.0.1";
  char *addr_str_tunnel_board = "10.0.1.2";
  char *addr_str_tunnel_ground = "10.0.1.1";
  char *addr_str_tunnel_mask = "255.255.255.0";

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  dev=0; maxdev=dev; 
#ifdef RAW                 
  if (argc!=2) exit(-1);
  int8_t antdbm;
  uint16_t datalen, radiotapvar,pos;
  uint32_t crc, crc_rx;
  uint32_t totfails = 0;
  int8_t droneid = 5;
  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };
  ((struct sock_filter *)&bpf_bytecode[1])->k = droneid; // Can be implemented by a drone ID (TODO)
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
  offsetraw=(sizeof(radiotaphdr)+sizeof(ieeehdr));
  build_crc32_table();
#else 
  if (argc!=1) exit(-1);
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
  if (-1 == bind(fd[dev], (struct sockaddr *)&addr_in[dev], sizeof(addr_in[dev]))) exit(-1);
  addr_out[dev].sin_family = AF_INET;
  addr_out[dev].sin_port = htons(5100); 
  offsetraw = 0;
#endif // def RAW
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  maxfd=fd[dev];

  dev=1; maxdev=dev;   // Tunnel (one bidirectional link)
  memset(&ifr, 0, sizeof(struct ifreq));
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
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  maxfd=fd[dev];
  if (-1 == (fd_tun_udp=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr.sin_family = AF_INET;
  memcpy(&ifr.ifr_addr,&addr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFADDR, &ifr ) < 0 ) exit(-1);
  addr.sin_addr.s_addr = inet_addr(addr_str_tunnel_mask);
  memcpy(&ifr.ifr_addr,&addr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFNETMASK, &ifr ) < 0 ) exit(-1);
  dstaddr.sin_family = AF_INET;
  memcpy(&ifr.ifr_addr,&dstaddr,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFDSTADDR, &ifr ) < 0 ) exit(-1);
  ifr.ifr_mtu = TUN_MTU;

  if (ioctl( fd_tun_udp, SIOCSIFMTU, &ifr ) < 0 ) exit(-1);
  ifr.ifr_flags = IFF_UP ;
  if (ioctl( fd_tun_udp, SIOCSIFFLAGS, &ifr ) < 0 ) exit(-1);

  dev=2; maxdev=dev;  // Video (one directional link)
  if (-1 == (fd[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
#if ROLE
  addr_in[dev].sin_family = AF_INET;
  addr_in[dev].sin_port = htons(5600);
  addr_in[dev].sin_addr.s_addr = inet_addr(addr_str_local);
  if (-1 == bind(fd[dev], (struct sockaddr *)&addr_in[dev], sizeof(addr_in[dev]))) exit(-1);
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  maxfd=fd[dev];
#else
  addr_out[dev].sin_family = AF_INET;
  addr_out[dev].sin_port = htons(5600);
  addr_out[dev].sin_addr.s_addr = inet_addr(addr_str_local);
#endif // ROLE  

  dev=3;             // Telemetry 
#if ROLE	     // option on board
  #if ROLE == 2       // option with telemetry (one bidirectional link)
    if (-1 == (fd[dev]=open(UART,O_RDWR | O_NOCTTY | O_NONBLOCK))) exit(-1);
    struct termios tty;
    if (0 != tcgetattr(fd[dev], &tty)) exit(-1);
    cfsetispeed(&tty,B115200);
    cfsetospeed(&tty,B115200);
    cfmakeraw(&tty);
    if (0 != tcsetattr(fd[dev], TCSANOW, &tty)) exit(-1);
    tcflush(fd[dev],TCIFLUSH);
    tcdrain(fd[dev]);
    if (fd[dev]>maxfd) maxfd=fd[dev];
    FD_SET(fd[dev], &(readset_ref));
    maxdev=dev;
  #endif // ROLE == 2
#else            // option on ground (two directional links)
  if (-1 == (fd[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_in[dev].sin_family = AF_INET;
  addr_in[dev].sin_port = htons(4245);
  addr_in[dev].sin_addr.s_addr = inet_addr(addr_str_local);
  if (-1 == bind(fd[dev], (struct sockaddr *)&addr_in[dev], sizeof(addr_in[dev]))) exit(-1);
  if (-1 == (fd_out[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out[dev].sin_family = AF_INET;
  addr_out[dev].sin_port = htons(4244);
  addr_out[dev].sin_addr.s_addr = inet_addr(addr_str_local);
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  maxdev=dev;
#endif // ROLE

  ptr = udp+sizeof(payhdr_t)+offsetraw;
  lensum=0;subpaynb=0;
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(maxfd + 1, &readset, NULL, NULL, &timeout);

    if (ret >0) {
      for (cpt = 0; cpt < (maxdev+1); cpt++) {
        if(FD_ISSET(fd[cpt], &readset)) {
          if (cpt == 0) {         
            len = read(fd[0], udp, UDP_SIZE);
#ifdef RAW	
            radiotapvar = (udp[2] + (udp[3] << 8)); // get variable radiotap header size
            pos = radiotapvar + sizeof(ieeehdr);
    	    antdbm = udp[31];
            payhdr_p = (payhdr_t *)(udp + pos);
            lensum = payhdr_p->len; 
      	    datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + lensum; 
            const uint8_t *s = &udp[radiotapvar];  // compute CRC32 after radiotap header
            crc=0xFFFFFFFF;
            for(uint32_t i=0;i<datalen;i++) {
              uint8_t ch=s[i];
              uint32_t t=(ch^crc)&0xFF;
              crc=(crc>>8)^crc32_table[t];
            }
      	    memcpy(&crc_rx, &udp[len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
            if (~crc != crc_rx) {totfails ++;crcok=false;}
	    else crcok = true;
      	    ptr=udp+pos+sizeof(payhdr_t);
#else
            payhdr_p = (payhdr_t *)(udp);
            lensum = payhdr_p->len; 
	    crcok = true;
      	    ptr=udp+sizeof(payhdr_t);
#endif // RAW
	    if (crcok) {
              seq = payhdr_p->seq; 
              if ((seq>1) && (seqprev != seq-1)) totdrops ++;
       	      seqprev = seq;
      	      while (lensum>0) {
                id = ((subpayhdr_t *)ptr)->id;
                len = ((subpayhdr_t *)ptr)->len;
#if ROLE
                len = write(fd[id], ptr + sizeof(subpayhdr_t), len);
#else 
                if (id==1)  len = write(fd[id], ptr + sizeof(subpayhdr_t), len);
		else len = sendto(fd[id], ptr + sizeof(subpayhdr_t), len, 0, (struct sockaddr *)&(addr_out[id]), sizeof(struct sockaddr));
#endif // ROLE
                ptr += (len+sizeof(subpayhdr_t));
                lensum -= (len+sizeof(subpayhdr_t));
  	      }
              ptr=udp+sizeof(payhdr_t)+offsetraw;
	    }
	  } else {
            len = read(fd[cpt], ptr+sizeof(subpayhdr_t), UDP_SIZE);
            ((subpayhdr_t *)ptr)->id=cpt;
            ((subpayhdr_t *)ptr)->len=len;
    	    ptr += (len+sizeof(subpayhdr_t));
    	    lensum += (len+sizeof(subpayhdr_t));
	    subpaylen[subpaynb++]=len;
          }
        }
      }           
      curr_p = udp;
      curr_cpt = 0;
      lenpay = lensum;
      while (lensum>0) {
	if (lensum > PAYLOAD_SIZE ) { // The payload must be sent by subpayloads. Looking to send joined subpayloads within the PAYLOAD_SIZE
          lentmp = 0;                 // Consequent calls are around 46000 ns, quite under 800 ns wifi limit. 
	  for (int i=curr_cpt;i<subpaynb;i++) {
            lentmp += (subpaylen[i]+sizeof(subpayhdr_t));
	    cpttmp = i;
	    if (lentmp > PAYLOAD_SIZE) break;
	    lenpay = lentmp;
	  }
	  curr_cpt = cpttmp+1;
          nextcurr_p = udp + lenpay;
	  nextlenpay = lensum - lenpay;
        }
        clock_gettime( CLOCK_REALTIME, &stp);
        stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
        ptr = curr_p + offsetraw;
        ((payhdr_t *)ptr)->seq = seqout;
        ((payhdr_t *)ptr)->len = lenpay;
        ((payhdr_t *)ptr)->stp_n = stp_n;
#ifdef RAW		   
        memcpy(curr_p,radiotaphdr,sizeof(radiotaphdr));
        ieeehdr[9] = droneid;
        memcpy(curr_p+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
        len = write(fd[0], curr_p, lenpay + sizeof(payhdr_t) + offsetraw);
#else
        len = sendto(fd[0], curr_p, lenpay + sizeof(payhdr_t), 0, (struct sockaddr *)&(addr_out[0]), sizeof(struct sockaddr));
#endif // RAW
        lensum -= lenpay;
        if (lensum==0) { ptr = udp+sizeof(payhdr_t)+offsetraw; seqout++; subpaynb=0;}
	else { curr_p = nextcurr_p; lenpay = nextlenpay; }
      }
    }
  }
}
