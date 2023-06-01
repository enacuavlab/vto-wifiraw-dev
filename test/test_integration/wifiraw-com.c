#include "wifiraw-com.h"

uint16_t ports[2][2]={{5600,4244},{5700,4245}};
//uint16_t ports[2][3]={{5600,4244,14900},{5700,4245,14800}};

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
void init(init_t *px) {

  char addr_str[20] = "127.0.0.1";

  px->log = fopen("/tmp/wifiraw.log", "a");
  setvbuf(px->log, NULL, _IONBF, 0);

  // This is the rx raw socket, at position 0 in the input file descriptor array
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
  if (-1 == (px->fd_in[0] = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(px->fd_in[0], F_GETFL))) exit(-1);
  if (-1 == (fcntl(px->fd_in[0], F_SETFL, flags | O_NONBLOCK))) exit(-1);
  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(px->fd_in[0], SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, px->node, sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( px->fd_in[0], SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(px->fd_in[0], (struct sockaddr *)&sll, sizeof(sll))) exit(-1);
  char drain[1];
  while (recv(px->fd_in[0], drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(px->fd_in[0], SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);
  px->maxfd = px->fd_in[0];
  FD_SET(px->fd_in[0], &(px->readset));

  // These are the rx udp sockets, following raw socket in the input file descriptor array
  uint8_t index; 
  if (px->role) index=0; else index=1;
  for (int i=2;i<4;i++) {
    if (-1 == (px->fd_in[i]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(ports[index][i-2]);
    addr_in.sin_addr.s_addr = inet_addr(addr_str);
    if (-1 == bind(px->fd_in[i], (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);
    if (px->fd_in[i] > px->maxfd) px->maxfd = px->fd_in[i];
    FD_SET(px->fd_in[i], &(px->readset));
  }

  // This is the tx raw socket, at position 0 in the ouput file descriptor array
  if (-1 == (px->fd_out[0]=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, px->node, sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( px->fd_out[0], SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(px->fd_out[0], (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  // These are the tx udp sockets, following raw socket in the outpout file descriptor array
  if (px->role) index=1; else index=0;
  for (int i=2;i<4;i++) {
    if (-1 == (px->fd_out[i]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    px->addr_out[i].sin_family = AF_INET;
    px->addr_out[i].sin_port = htons(ports[index][i-2]);
    px->addr_out[i].sin_addr.s_addr = inet_addr(addr_str);
  }

  // Tunnel Interface and associated socket
  if (0 > (px->fd_in[1]=open("/dev/net/tun",O_RDWR))) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (px->role) strcpy(ifr.ifr_name,"airtun"); else strcpy(ifr.ifr_name, "grdtun");
  if (ioctl( px->fd_in[1], TUNSETIFF, &ifr ) < 0 ) exit(-1);
  if (px->fd_in[1] > px->maxfd) px->maxfd = px->fd_in[1];
  FD_SET(px->fd_in[1], &(px->readset));

  int16_t fd;
  if (-1 == (fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  struct sockaddr_in addr_in;
  addr_in.sin_family = AF_INET;
  if (px->role) addr_in.sin_addr.s_addr = inet_addr("10.0.1.2");
  else addr_in.sin_addr.s_addr = inet_addr("10.0.1.1");
  memcpy(&ifr.ifr_addr,&addr_in,sizeof(struct sockaddr));
  if (ioctl( fd, SIOCSIFADDR, &ifr ) < 0 ) exit(-1);
  addr_in.sin_family = AF_INET;
  addr_in.sin_addr.s_addr = inet_addr("255.255.255.0");
  memcpy(&ifr.ifr_addr,&addr_in,sizeof(struct sockaddr));
  if (ioctl( fd, SIOCSIFNETMASK, &ifr ) < 0 ) exit(-1);
  ifr.ifr_mtu = 1400;
  if (ioctl( fd, SIOCSIFMTU, &ifr ) < 0 ) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  if (px->role) strcpy(ifr.ifr_name,"airtun"); else strcpy(ifr.ifr_name, "grdtun");
  ifr.ifr_flags = IFF_UP ;
  if (ioctl( fd, SIOCSIFFLAGS, &ifr ) < 0 ) exit(-1);

  build_crc32_table();
}
