#include "wifiraw-com-mux.h"

/*

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

BOARD
sudo ./wifiraw 1  $node

GROUND
sudo ./wifiraw 0  $node

*/

uint16_t subpayloadmaxlen[]={0,TUNEL_SIZE,TELEM_SIZE,VIDEO_SIZE};

/*****************************************************************************/
int main(int argc, char *argv[]) {

   setpriority(PRIO_PROCESS, 0, -10);

  if ((argc==1)||(argc>3)) exit(-1);
  init_t px;
  px.role = atoi(argv[1]);
  if (px.role > 2) exit(-1);
  strcpy(px.node,argv[argc - 1]);
  init(&px);

  double  kbytesec;
  uint8_t udp[UDP_SIZE];

  uint16_t subpaylen = 0, seq = 1, ret;
  int32_t paylen=0;
  uint64_t stp_n,now_n,lastime_n,timeleft_n,elapse_n,start_n;

  struct timespec stp,timeleft,now;
  struct timeval timeout;

  ssize_t len;
  fd_set readset;

  payhdr_t *payhead;
  subpayhdr_t *subpayhead;
  uint8_t *subppay;

  int8_t u8Antdbm, id;
  uint16_t u16HeaderLen, pos, datalen, seqprev=1, totbytes = 0 ;
  uint32_t crc, crc_rx;
  uint32_t totfails = 0, totdrops = 0;


  for(;;) {
    FD_ZERO(&readset);
    readset = px.readset;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(1 + px.maxfd, &readset, NULL, NULL, &timeout);
    for (id = 0; id  < 4 && ret > 0; id++) {
      if(FD_ISSET(px.fd[id], &readset)) {
	if (id == 0) {                                     // read raw and send to udp and/or uart
          len = read(px.fd[0], udp, FULL_PKT_SIZE);
          if (len > 0) {
            clock_gettime( CLOCK_REALTIME, &now);
            u16HeaderLen = (udp[2] + (udp[3] << 8)); // get variable radiotap header size
            pos = u16HeaderLen + sizeof(ieee_hdr_data);
    	    u8Antdbm = udp[31];
            payhead = (payhdr_t *)(udp + pos);
            seq = payhead->seq;
            paylen = payhead->len;                          // this len do not include pay_hdr_t
	    totbytes += paylen;
            stp_n = payhead->stp_n;
      	    datalen = sizeof(ieee_hdr_data) + sizeof(payhdr_t) + paylen; 
            const uint8_t *s = &udp[u16HeaderLen];  // compute CRC32 after radiotap header
            crc=0xFFFFFFFF;
            for(uint32_t i=0;i<datalen;i++) {
              uint8_t ch=s[i];
              uint32_t t=(ch^crc)&0xFF;
              crc=(crc>>8)^crc32_table[t];
            }
      	    memcpy(&crc_rx, &udp[len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
            if (~crc != crc_rx) totfails ++;
      	    else {
      	      if ((seq>1) && (seqprev != seq-1)) totdrops ++;
      	      seqprev = seq;
              subpayhead = (subpayhdr_t *)(udp + pos + sizeof(payhdr_t));
              subppay = udp + pos + sizeof(payhdr_t) + sizeof(subpayhdr_t);
	      while (paylen > 0) {
                id = subpayhead->id;
                subpaylen = subpayhead->len;
		if (id == 1) len = write(px.fd[1], subppay, subpaylen);  // On Board and Ground write Tunnel (udp)
		else {
		  if (px.role) { // On Board write Telemetry (uart)
                    len = write(px.fd[id], subppay, subpaylen);  
		  } else {      // On Ground : Telemetry (udp), Video (udp)
                    len = sendto(px.fd_out[id-2], subppay, subpaylen, 0, (struct sockaddr *)&(px.addr_out[id-2]), sizeof(struct sockaddr));
		  }
		}
		paylen -= (subpaylen + sizeof(subpayhdr_t));
                if (paylen > 0) { 
		  subpayhead = (subpayhdr_t *)((uint8_t *)(subpayhead) + subpaylen);
                  subppay += (subpaylen + sizeof(subpayhdr_t));
		  printf("Twice\n");
		}
	      }
            }
          }
        } else {   // On Board and Ground read Tunnel (udp); On Board read Telemetry (uart), Video (udp); On Ground : read Telemetry (udp) 
		   // send to raw 
	  if (paylen == 0) subppay = udp + offset1 ;
	  else subppay += len;
          len = read(px.fd[id], subppay + sizeof(subpayhdr_t), subpayloadmaxlen[id]);
          subpayhead = (subpayhdr_t *)subppay;
          subpayhead->id = id;
          subpayhead->len = len;
	  paylen += (sizeof(subpayhdr_t) + len);
	}
      }
    }

    if (paylen > 1403) printf("(%d)\n",paylen);

    if (paylen > 0) {
      memcpy( udp, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
      ieee_hdr_data[9] = 5;
      memcpy( udp + sizeof(uint8_taRadiotapHeader), ieee_hdr_data, sizeof(ieee_hdr_data));
      payhead = (payhdr_t *)(udp + offset0);
      payhead->seq = seq;
      payhead->len = paylen;
      clock_gettime( CLOCK_REALTIME, &stp);
      stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
      payhead->stp_n = stp_n;
      ssize_t dump = write(px.fd[0], udp, paylen + offset1);
      totbytes += paylen;
      clock_gettime( CLOCK_REALTIME, &now);
      now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
      if (seq == 1) { timeleft.tv_sec = 0; timeleft.tv_nsec = 800; }
      else {
        timeleft_n = lastime_n + 800 - now_n;
        if ( (lastime_n + 800) < now_n) { timeleft.tv_nsec = 0; timeleft.tv_sec = 0; }
        else { 
          timeleft_n = lastime_n + 800 - now_n;
          timeleft.tv_sec = timeleft_n / (uint64_t)1000000000;
          timeleft.tv_nsec = timeleft_n % (uint64_t)1000000000;
        }
      }
      lastime_n = now_n;
      while (nanosleep(&timeleft, NULL)); // Constant time delay between each packet sent
      paylen = 0;
      seq++;
    }
  
    clock_gettime( CLOCK_REALTIME, &now);
    now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
    if (seq != 1) { // Compute cyclic byte rate
      elapse_n = now_n - start_n;
      if (elapse_n > 1000000000L) { kbytesec = ((double)totbytes / elapse_n * 1000000); start_n = now_n; 
	      printf("(%d)\n",totbytes);
	      totbytes = 0; 
        fprintf(px.log,"kbytesec(%d)fails(%d)drops(%d)dbm(%d)\n",(uint16_t)kbytesec,totfails,totdrops,u8Antdbm); }
    } else start_n = now_n;
  }
}
