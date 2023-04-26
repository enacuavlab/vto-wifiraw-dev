#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t  param_portid = 5;

  setpriority(PRIO_PROCESS, 0, -10);

  uint16_t headerSize0 = sizeof(uint8_taRadiotapHeader) + sizeof(ieee_hdr_llc) + sizeof(ieee_hdr_data); 
  uint16_t headerSize1 = headerSize0 + sizeof(pay_hdr_t);            

  uint8_t *pu8;
  uint8_t cpt_d=0, fec_d = FEC_D;
  uint32_t len_d[fec_d];
  uint8_t buf_d[fec_d][28 + 24 + 4 + 2 + 1400 + 12];
  for (uint8_t i=0;i<fec_d;i++) {
    len_d[i] = 0;
    pu8 = buf_d[i];
    memset(pu8, 0, sizeof (28 + 24 + 4 + 2 + 1400 +12 ));
    memcpy(pu8, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
    pu8 += sizeof(uint8_taRadiotapHeader);
    memcpy(pu8, ieee_hdr_data, sizeof(ieee_hdr_data));
    pu8 += sizeof(ieee_hdr_data);
    memcpy(pu8, ieee_hdr_llc, sizeof(ieee_hdr_llc));
    buf_d[i][32] = param_portid;
  }

  uint16_t fd_in = STDIN_FILENO;
/*
  uint16_t fd_in = 0;
  if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(5000);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  if (-1 == bind(fd_in, (struct sockaddr *)&addr, sizeof(addr))) exit(-1);
*/
  uint16_t fd_out = 0;
  if (-1 == (fd_out=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, argv[1], sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( fd_out, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(fd_out, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  struct timeval timeout;
  struct timespec stp;
  uint64_t stp_n, delay_n=0;
  uint32_t inl, data_size = 1400;
  uint16_t offset,len,seq=0,wait_u,delta_u,r;
  uint8_t di;
  uint8_t *ppay;
  pay_hdr_t *phead;

  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd_in, &readset);
    timeout.tv_sec = 1;
    r = select(fd_in + 1, &readset, NULL, NULL, &timeout);
    if (r > 0) {     
      if (len_d[cpt_d] == 0) offset = 58 +12 ; // max limit be carreful to not overshoot buffer
      pu8 = buf_d[cpt_d];
      ppay = (pu8 + offset);
      inl = read(fd_in, ppay, data_size - len_d[cpt_d] );   // fill pkts with read input
      if (inl < 0) continue;
      len_d[cpt_d] += inl;
      offset += inl;
      if (len_d[cpt_d] == data_size) cpt_d++;
      if (cpt_d == fec_d) r = 0;
    }
    if (r == 0) {
      if (len_d[0] > 0) {
        di = 0;
        while (di < fec_d) {
	  if (len_d[di] == 0) di = fec_d;
	  else {
            pu8 = buf_d[di];

	    len = len_d[di] ; len_d[di] = 0; di ++;

            clock_gettime( CLOCK_MONOTONIC, &stp);
            stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

	    phead = (pay_hdr_t *)(pu8 + 58);
            phead->seq = seq;
            phead->len = len;
            phead->stp_n = stp_n;

            r = write(fd_out, pu8, PKT_SIZE_0);
            if (r != PKT_SIZE_0) exit(-1);

	    ppay = (pu8 + 58 + 12);
            write(STDOUT_FILENO, ppay, len);

	    delta_u = (stp_n - delay_n)/1000;
	    if (delta_u > 400) wait_u = 0;
	    delay_n = stp_n;
	    usleep(wait_u);
	  }
	}
	cpt_d = 0; di = 0;
        if (seq == 65535)  seq = 0;  else seq++;
      }
    }
  }
}
