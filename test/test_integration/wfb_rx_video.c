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
  0x07, 0x00, 0x04,       // MCS flags (0x07), 0x0, rate index (0x04)
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

  struct sockaddr_in addr_out[FD_NB];
  uint8_t udp[UDP_SIZE], *ptr, *ptrhd;
  uint16_t fd[FD_NB],dev,maxdev,maxfd=0,ret,seq,seqprev,id,subpaynb;
  uint32_t totdrops=0;
  bool crcok = false;
  int8_t offsetraw,antdbm;
  int32_t lensum=0;
  struct ifreq ifr;
  ssize_t len;
  struct timeval timeout;
  char *addr_str_local = "127.0.0.1";

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  dev=0; maxdev=dev; 
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
  if (fd[dev]>maxfd) maxfd=fd[dev];
  FD_SET(fd[dev], &(readset_ref));
  maxfd=fd[dev];

  dev=2; maxdev=dev;  // Video (one directional link)
  if (-1 == (fd[dev]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out[dev].sin_family = AF_INET;
  addr_out[dev].sin_port = htons(5700);
  addr_out[dev].sin_addr.s_addr = inet_addr(addr_str_local);

  ptr = udp+sizeof(payhdr_t)+offsetraw;
  lensum=0;subpaynb=0;
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(maxfd + 1, &readset, NULL, NULL, &timeout);

    if (ret >0) {
      for (int cpt = 0; cpt < (maxdev+1); cpt++) {
        if(FD_ISSET(fd[cpt], &readset)) {
          if (cpt == 0) {         
            len = read(fd[0], udp, UDP_SIZE);

            printf("IN (%ld)\n",len);

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
      	    ptrhd=udp+pos+sizeof(payhdr_t);
	    if (crcok) {
              seq = payhdr_p->seq; 
              if ((seq>1) && (seqprev != seq-1)) totdrops ++;
       	      seqprev = seq;
      	      if (lensum>0) {
                id = ((subpayhdr_t *)ptrhd)->id;
                len = ((subpayhdr_t *)ptrhd)->len;
		len = sendto(fd[id], ptrhd + sizeof(subpayhdr_t), len, 0, (struct sockaddr *)&(addr_out[id]), sizeof(struct sockaddr));

		printf("(%d) OUT (%ld)\n",totdrops,len);

  	      }
	    }
	  } 
        }
      }           
    }
  }
}
