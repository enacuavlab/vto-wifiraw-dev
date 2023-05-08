#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "inject_capt.h"

/*
The tx_raw program gets stream input from STDIN or from UDP Port, and output to raw wifi and optionnaly STDOUT


1) 
sudo ./tx_raw $node

2)
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=5000 ! fdsink | sudo ./tx_raw $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false

3)
gst-launch-1.0 videotestsrc ! 'video/x-raw,width=1280,height=720,format=NV12,framerate=30/1' ! timeoverlay ! x264enc  tune=zerolatency bitrate=5000 speed-preset=superfast ! rtph264pay mtu=1400 ! udpsink port=5000 host=127.0.0.1

sudo ./tx_raw 127.0.0.1:5000 $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false




*/
/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint32_t param_data_size = 1400;

  setpriority(PRIO_PROCESS, 0, -10);

  char node[20],addr_str[20];
  uint16_t port=0;

  if ((argc==1)||(argc>3)) exit(-1);
  if (argc>1) strcpy(node,argv[argc - 1]);
  if (argc==3) { char *ch=strtok(argv[1],":"); strcpy(addr_str,&ch[0]); port=atoi(strtok(NULL,":")); }

  uint8_t  param_portid = 5;

  uint8_t *pu8;
  uint8_t cpt_d=0, fec_d = FEC_D;
  uint32_t len_d[fec_d];
  uint8_t buf_d[fec_d][PKT_SIZE_0];
  for (uint8_t i=0;i<fec_d;i++) {
    len_d[i] = 0;
    pu8 = buf_d[i];
    memset(pu8, 0, PKT_SIZE_0);
    memcpy(pu8, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
    pu8 += sizeof(uint8_taRadiotapHeader);
    ieee_hdr_data[9] = param_portid;
    memcpy(pu8, ieee_hdr_data, sizeof(ieee_hdr_data));
  }

  uint16_t fd_in; 
  if (port==0) { 
    fd_in = STDIN_FILENO;       /* Turn off canonical processing on stdin*/
    static struct termios mode;
    tcgetattr( fd_in, &mode);
    mode.c_lflag &= ~(ECHO | ICANON);
    mode.c_cc[VMIN] = param_data_size;
    mode.c_cc[VTIME] = 10;
    tcsetattr( fd_in, TCSANOW, &mode);
    fcntl(fd_in, F_SETFL, O_NONBLOCK);
  } else {
    if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(addr_str);
    if (-1 == bind(fd_in, (struct sockaddr *)&addr, sizeof(addr))) exit(-1);
  }

  uint16_t fd_out = 0;
  if (-1 == (fd_out=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW))) exit(-1);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy( ifr.ifr_name, node, sizeof( ifr.ifr_name ) - 1 );
  if( ioctl( fd_out, SIOCGIFINDEX, &ifr ) < 0 ) exit(-1);
  struct sockaddr_ll sll;
  memset( &sll, 0, sizeof( sll ) );
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifr.ifr_ifindex;
  sll.sll_protocol = htons( ETH_P_ALL );
  if (-1 == bind(fd_out, (struct sockaddr *)&sll, sizeof(sll))) exit(-1);

  uint16_t offset0 = sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data);
  uint16_t offset1 = offset0 + sizeof(pay_hdr_t);

  struct timeval timeout;
  struct timespec stp;
  uint64_t stp_n;
  uint32_t inl;
  uint16_t offset,len,seq=1,r;
  uint8_t di;
  uint8_t *ppay;
  pay_hdr_t *phead;

  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(fd_in, &readset);
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    r = select(fd_in + 1, &readset, NULL, NULL, &timeout);
    if (r > 0) {     
      if (len_d[cpt_d] == 0) offset = offset1 ; // max limit be carreful to not overshoot buffer
      pu8 = buf_d[cpt_d];
      ppay = (pu8 + offset);
      inl = read(fd_in, ppay, param_data_size - len_d[cpt_d] );   // fill pkts with read input
      if (inl ==  0) {
        if (len_d[0] > 0) r=0;
        else exit(-1); // TODO select returning data to read, but no data available to read (close (stdin)
      }
      if (inl < 0) continue;
      len_d[cpt_d] += inl;
      offset += inl;
      if (len_d[cpt_d] == param_data_size) cpt_d++;
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

            phead = (pay_hdr_t *)(pu8 + offset0);
            phead->seq = seq;
            phead->len = len;

            clock_gettime( CLOCK_MONOTONIC, &stp);
            stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

            phead->stp_n = stp_n;
            r = write(fd_out, pu8, PKT_SIZE_0);
            if (r != PKT_SIZE_0) exit(-1);

            ppay = (pu8 + offset1);
//            write(STDOUT_FILENO, ppay, len);
            printf("(%d)(%d)(%ld)\n",seq,len,stp_n);

	    usleep(800);
	  }
	}
	cpt_d=0;
	if (seq == 65535)  seq = 1;  else seq++;
      }
    }
  }
}
