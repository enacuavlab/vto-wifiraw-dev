#include "multi-aio-raw-com.h"

uint16_t onboardports[]={5600,4244,14900};
uint16_t ongroundports[]={5700,4245,14800};

/*****************************************************************************/
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

/*****************************************************************************/
void init_tx(init_tx_t *ptx) {

  char addr_str[20] = "127.0.0.1";

  ptx->log = fopen("/tmp/tx.log", "a");
  setvbuf(ptx->log, NULL, _IONBF, 0);

  ptx->maxfd = 0;
  for (int i=0;i<3;i++) {
    if (-1 == (ptx->fd_in[i]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(onboardports[i]);
    addr_in.sin_addr.s_addr = inet_addr(addr_str);
    if (-1 == bind(ptx->fd_in[i], (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);
    if (ptx->fd_in[i] > ptx->maxfd) ptx->maxfd = ptx->fd_in[i];
    FD_SET(ptx->fd_in[i], &(ptx->readset));
  }

  if (-1 == (ptx->fd_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, ptx->node, sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( ptx->fd_raw, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(ptx->fd_raw, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);
}

/*****************************************************************************/
void init_rx(init_rx_t *prx) {

  char addr_str[20] = "127.0.0.1";

  prx->log = fopen("/tmp/rx.log", "a");
  setvbuf(prx->log, NULL, _IONBF, 0);

  struct sock_filter bpf_bytecode[] = { 
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
    { 0x15,  0,  1, 0x00000000 }, // Jeq = 0x15, if A equal port_id (updated while run) then proceed next line, else jump one line
    { 0x06,  0,  0, 0xffffffff }, // Ret = 0x06,  accept packet => return !0 
    { 0x06,  0,  0, 0x00000000 }, // Ret = 0x06, reject packet => return 0 
  };

  ((struct sock_filter *)&bpf_bytecode[1])->k = 5;
  struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};

  uint8_t flags;
  uint16_t protocol = htons(ETH_P_ALL); 
  if (-1 == (prx->fd_raw = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(prx->fd_raw, F_GETFL))) exit(-1);
  if (-1 == (fcntl(prx->fd_raw, F_SETFL, flags | O_NONBLOCK))) exit(-1);

  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(prx->fd_raw, SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, prx->node, sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( prx->fd_raw, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(prx->fd_raw, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  char drain[1];
  while (recv(prx->fd_raw, drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(prx->fd_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);

  for (int i=0;i<3;i++) {
    if (-1 == (prx->fd_out[i]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    prx->addr_out[i].sin_family = AF_INET;
    prx->addr_out[i].sin_port = htons(ongroundports[i]);
    prx->addr_out[i].sin_addr.s_addr = inet_addr(addr_str);
  }

  build_crc32_table();
}
