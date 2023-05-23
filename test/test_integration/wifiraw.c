#include "wifiraw-com.h"

/*

BOARD
sudo ./wifiraw 1  $node

GROUND
sudo ./wifiraw 0  $node

*/

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
  uint8_t udp_in[UDP_SIZE];
  uint16_t len = 0, offset = 0, seq = 1, len_tag, ret;
  uint64_t stp_n,now_n,lastime_n,timeleft_n,elapse_n,start_n;
  struct timespec stp,timeleft,now;
  struct timeval timeout;
  ssize_t len_in, len_out;
  fd_set readset;
  pay_hdr_t *phead;

  uint8_t udp_out[UDP_SIZE];
  uint8_t *ppay;
  int8_t u8Antdbm, id;
  uint16_t u16HeaderLen, pos, datalen, seqprev=1, totrcv = 0 ;
  uint32_t crc, crc_rx;
  bool lastpkt = false;
  uint32_t totfails = 0, totdrops = 0;


  for(;;) {
    FD_ZERO(&readset);
    readset = px.readset;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(1 + px.maxfd, &readset, NULL, NULL, &timeout);
    for (id = 0; id  < 4 && ret > 0; id++) {
      if(FD_ISSET(px.fd_in[id], &readset)) {
	if (id == 0) {                                     // read raw and send to udp
          len_in = read(px.fd_in[0], udp_in, PKT_SIZE_1_IN);
          if (len_in > 0) {
      
            clock_gettime( CLOCK_REALTIME, &now);
            u16HeaderLen = (udp_in[2] + (udp_in[3] << 8)); // get variable radiotap header size
            pos = u16HeaderLen + sizeof(ieee_hdr_data);
      
    	    u8Antdbm = udp_in[31];
    
            phead = (pay_hdr_t *)(udp_in + pos);
            id = phead->id;
            seq = phead->seq;
            len = phead->len;                          // this len do not include pay_hdr_t
            stp_n = phead->stp_n;
      
      	    if (len & (1UL << 15)) { len &= (~(1U << 15)); lastpkt = true; } // check end packet segment 
      
      	    datalen = sizeof(ieee_hdr_data) + sizeof(pay_hdr_t) + len; 
            const uint8_t *s = &udp_in[u16HeaderLen];  // compute CRC32 after radiotap header
            crc=0xFFFFFFFF;
            for(uint32_t i=0;i<datalen;i++) {
              uint8_t ch=s[i];
              uint32_t t=(ch^crc)&0xFF;
              crc=(crc>>8)^crc32_table[t];
            }
      	    memcpy(&crc_rx, &udp_in[len_in - 4], sizeof(crc_rx)); // CRC32 : last four bytes
      								
            if (~crc != crc_rx) totfails ++;
      	    else {
              ppay = (udp_in + pos + sizeof(pay_hdr_t));
              memcpy(udp_out + offset , ppay, len);
              offset += len;
        
              if (lastpkt)  {
                len_out = sendto(px.fd_out[id], udp_out, offset, 0, (struct sockaddr *)&(px.addr_out[id]), sizeof(struct sockaddr));
                offset = 0; lastpkt = false;
      	        if ((seq>1) && (seqprev != seq-1)) totdrops ++;
      	        seqprev = seq;
              }
            }
          }
        } else {                                      // read udp and send to raw

          len_in = read(px.fd_in[id], udp_in + offset1, UDP_SIZE - offset1);
          offset = 0;
          while (len_in > 0) {
            if (len_in > DATA_SIZE) { len = DATA_SIZE; len_tag = len; }
            else { len = len_in; len_tag = len; (len_tag |= 1UL << 15); } // Set signed bit of unsigned length to signal  sequence end
          
            memcpy( udp_in + offset, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  	    ieee_hdr_data[9] = 5;
            memcpy( udp_in + offset + sizeof(uint8_taRadiotapHeader), ieee_hdr_data, sizeof(ieee_hdr_data));
            phead = (pay_hdr_t *)(udp_in + offset + offset0);
            phead->id = id;
            phead->seq = seq;
            phead->len = len_tag;
            clock_gettime( CLOCK_REALTIME, &stp);
            stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
            phead->stp_n = stp_n;
               
            write(px.fd_out[0], udp_in + offset, len + offset1);
      
            offset += len;
            len_in -= len;
     
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
          }
	}
  
        clock_gettime( CLOCK_REALTIME, &now);
        now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
        if (seq != 1) { // Compute cyclic byte rate
          elapse_n = now_n - start_n;
          if (elapse_n > 1000000000L) { kbytesec = ((double)totrcv / elapse_n * 1000000); start_n = now_n; totrcv = 0; 
                                      fprintf(px.log,"kbytesec(%d)fails(%d)drops(%d)dbm(%d)\n",(uint16_t)kbytesec,totfails,totdrops,u8Antdbm); }
        } else start_n = now_n;
        totrcv += len_out;
      }
    }
  }
}
