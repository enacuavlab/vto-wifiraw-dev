#include "wifiraw-com-mux.h"

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
  
  // This is duplex raw socket
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
  if (-1 == (px->fd[0] = socket(AF_PACKET,SOCK_RAW,protocol))) exit(-1);
  if (-1 == (flags = fcntl(px->fd[0], F_GETFL))) exit(-1);
  if (-1 == (fcntl(px->fd[0], F_SETFL, flags | O_NONBLOCK))) exit(-1);
  struct sock_filter zero_bytecode = BPF_STMT(BPF_RET | BPF_K, 0);
  struct sock_fprog zero_program = { 1, &zero_bytecode};
  if (-1 == setsockopt(px->fd[0], SOL_SOCKET, SO_ATTACH_FILTER, &zero_program, sizeof(zero_program))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, px->node, sizeof( ifr.ifr_name ) - 1 );
  if (ioctl( px->fd[0], SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = protocol;
  if (-1 == bind(px->fd[0], (struct sockaddr *)&sll, sizeof(sll))) exit(-1);
  char drain[1];
  while (recv(px->fd[0], drain, sizeof(drain), MSG_DONTWAIT) >= 0) {
    printf("----\n");
  };
  if (-1 == setsockopt(px->fd[0], SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program))) exit(-1);
  px->maxfd = px->fd[0];
  FD_SET(px->fd[0], &(px->readset));


  // This is the duplex tunnel interface and  associated one bidirectional socket
  if (0 > (px->fd[1]=open("/dev/net/tun",O_RDWR))) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (px->role) strcpy(ifr.ifr_name,"airtun"); else strcpy(ifr.ifr_name, "grdtun");
  if (ioctl( px->fd[1], TUNSETIFF, &ifr ) < 0 ) exit(-1);
  if (px->fd[1] > px->maxfd) px->maxfd = px->fd[1];
  FD_SET(px->fd[1], &(px->readset));
  int16_t fd_tun_udp;
  if (-1 == (fd_tun_udp=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  struct sockaddr_in addr_in;
  addr_in.sin_family = AF_INET;
  if (px->role) addr_in.sin_addr.s_addr = inet_addr("10.0.1.2");
  else addr_in.sin_addr.s_addr = inet_addr("10.0.1.1");
  memcpy(&ifr.ifr_addr,&addr_in,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFADDR, &ifr ) < 0 ) exit(-1);
  addr_in.sin_family = AF_INET;
  addr_in.sin_addr.s_addr = inet_addr("255.255.255.0");
  memcpy(&ifr.ifr_addr,&addr_in,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFNETMASK, &ifr ) < 0 ) exit(-1);
  addr_in.sin_family = AF_INET;
  if (px->role) addr_in.sin_addr.s_addr = inet_addr("10.0.1.1");
  else addr_in.sin_addr.s_addr = inet_addr("10.0.1.2");
  memcpy(&ifr.ifr_addr,&addr_in,sizeof(struct sockaddr));
  if (ioctl( fd_tun_udp, SIOCSIFDSTADDR, &ifr ) < 0 ) exit(-1);
  ifr.ifr_mtu = 1400;
  if (ioctl( fd_tun_udp, SIOCSIFMTU, &ifr ) < 0 ) exit(-1);
  memset(&ifr, 0, sizeof(struct ifreq));
  if (px->role) strcpy(ifr.ifr_name,"airtun"); else strcpy(ifr.ifr_name, "grdtun");
  ifr.ifr_flags = IFF_UP ;
  if (ioctl( fd_tun_udp, SIOCSIFFLAGS, &ifr ) < 0 ) exit(-1);

  struct sockaddr_in addr;

  // This is the duplex telemetry and associated two unidirectional sockets
  if (px->role) {
    if (-1 == (px->fd[2]=open("/dev/ttyAMA0",O_RDWR | O_NOCTTY | O_NONBLOCK))) exit(-1);
    struct termios tty;
    if (0 != tcgetattr(px->fd[2], &tty)) exit(-1);
    cfsetispeed(&tty,B115200);
    cfsetospeed(&tty,B115200);
    cfmakeraw(&tty);
    if (0 != tcsetattr(px->fd[2], TCSANOW, &tty)) exit(-1);
    tcflush(px->fd[2],TCIFLUSH);
    tcdrain(px->fd[2]);
    if (px->fd[2] > px->maxfd) px->maxfd = px->fd[2];
    FD_SET(px->fd[2], &(px->readset));
  } else {
    if (-1 == (px->fd[2]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4245);
    addr.sin_addr.s_addr = inet_addr(addr_str);
    if (-1 == bind(px->fd[2], (struct sockaddr *)&addr, sizeof(addr))) exit(-1);
    if (-1 == (px->fd_out[0]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    px->addr_out[0].sin_family = AF_INET;
    px->addr_out[0].sin_port = htons(4244);
    px->addr_out[0].sin_addr.s_addr = inet_addr(addr_str);
    if (px->fd[2] > px->maxfd) px->maxfd = px->fd[2];
    FD_SET(px->fd[2], &(px->readset));
  }

  // This is the unidirectional video socket
  if (-1 == (px->fd[3]=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  px->fd_out[1] = px->fd[3];
  px->addr_out[1].sin_family = AF_INET;
  px->addr_out[1].sin_port = htons(5600);
  px->addr_out[1].sin_addr.s_addr = inet_addr(addr_str);
  if (px->role) {
    if (-1 == bind(px->fd[3], (struct sockaddr *)&(px->addr_out[1]), sizeof(addr))) exit(-1);
    if (px->fd[3] > px->maxfd) px->maxfd = px->fd[3];
    FD_SET(px->fd[3], &(px->readset));
  } 

  build_crc32_table();
}
