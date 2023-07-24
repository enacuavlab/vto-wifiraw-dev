#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <unistd.h>
#include <fcntl.h>

#include "inject_capt.h"

// Extra size is added to get variable radiotap header
#define UDP_SIZE (PKT_SIZE_1 + 200)

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
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint32_t port = 5;

  struct sock_filter bpf_bytecode[] = { 
#ifdef LEGACY
    { 0x30,  0,  0, 0x00000029 }, // Ldb = 0x30, load one byte at position 0x29 (offset = 41) to A
#else	  
    { 0x30,  0,  0, 0x0000002c }, // Ldb = 0x30, load one byte at position 0x2c (offset = 44) to A
#endif	  
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

  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);
  FD_SET(fd, &(readset_ref));

  bool crcok = false;
  int8_t antdbm;
  int32_t lensum=0;
  uint8_t udp[UDP_SIZE];
  struct timeval timeout;
  struct timespec stp;
  ssize_t len;
  uint16_t ret,radiotapvar,pos,datalen,seq,seqprev;
  uint32_t crc, crc_rx, drops=0, fails=0;
  uint64_t stp_n,stp_prev_n=0,inter_n=0,lentot=0,timetot_n=0;
  float byterate=0.0,minrate=0.0,maxrate=0.0;
  pay_hdr_t *payhdr_p; 

  build_crc32_table();
  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(fd + 1, &readset, NULL, NULL, &timeout);
    if (ret >0) {
      len = read(fd, udp, UDP_SIZE);

      clock_gettime( CLOCK_MONOTONIC, &stp);
      stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
      if (stp_prev_n != 0) inter_n = stp_n - stp_prev_n;
      stp_prev_n = stp_n;

      radiotapvar = (udp[2] + (udp[3] << 8)); // get variable radiotap header size
      pos = radiotapvar + sizeof(ieee_hdr_data);
      antdbm = udp[31];
      payhdr_p = (pay_hdr_t *)(udp + pos);
      lensum = payhdr_p->len; 
      datalen = sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + lensum; 
      const uint8_t *s = &udp[radiotapvar];  // compute CRC32 after radiotap header
      crc=0xFFFFFFFF;
      for(uint32_t i=0;i<datalen;i++) {
        uint8_t ch=s[i];
        uint32_t t=(ch^crc)&0xFF;
        crc=(crc>>8)^crc32_table[t];
      }
      memcpy(&crc_rx, &udp[len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
      if (~crc != crc_rx) {fails++ ; crcok=false;}
      else crcok = true;
      if (crcok) {
        seq = payhdr_p->seq; 
        len = payhdr_p->len; 
        stp_n = payhdr_p->stp_n; 
        if ((seq>1) && (seqprev != seq-1)) drops++;
        seqprev = seq;
        lentot += len;
	timetot_n += inter_n;
      }
      if (inter_n != 0) {
        byterate = (1000.0 * (float)len / ((float)inter_n));      
      }
      if (minrate == 0.0) minrate=byterate;
      if (maxrate == 0.0) maxrate=byterate;
      if (byterate < minrate) minrate = byterate;
      if (byterate > maxrate) maxrate = byterate;

      printf("(%d)(%ld)(%ld)(%d)(%d)(%f)(%f)\n",seq,len,stp_n,drops,fails,(float)(inter_n / 1000000.0),byterate);
      printf("(%f)(%f)(%f)\n",(1000.0 * (float)lentot / ((float)timetot_n)),minrate,maxrate);
    }
  }
}
