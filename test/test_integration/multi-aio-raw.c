#include "multi-aio-raw-com.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

   setpriority(PRIO_PROCESS, 0, -10);

  if ((argc==1)||(argc>3)) exit(-1);
  uint8_t role =atoi(argv[1]);
  if (!role) {

    init_tx_t ptx;
    strcpy(ptx.node,argv[argc - 1]);
    init_tx(&ptx);

    double  kbytesec;
    uint8_t udp_in[UDP_SIZE];
    uint16_t len = 0, offset = 0, seq = 1, len_tag, ret, totsnd=0;
    uint64_t stp_n,now_n,lastime_n,timeleft_n,elapse_n,start_n;
    struct timespec stp,timeleft,now;
    struct timeval timeout;
    ssize_t len_in;
    fd_set readset;
    pay_hdr_t *phead;
 
    for(;;) {
      FD_ZERO(&readset);
      readset = ptx.readset;
      timeout.tv_sec = 1; timeout.tv_usec = 0;
      ret = select(1 + ptx.maxfd, &readset, NULL, NULL, &timeout);
      for (uint8_t id = 0; id  < 3 && ret > 0; id++) {
        if(FD_ISSET(ptx.fd_in[id], &readset)) {
          len_in = read(ptx.fd_in[id], udp_in + offset1, UDP_SIZE - offset1);
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
               
            write(ptx.fd_raw, udp_in + offset, len + offset1);
      
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
  
          clock_gettime( CLOCK_REALTIME, &now);
          now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
  	  if (seq != 1) { // Compute cyclic byte rate
            elapse_n = now_n - start_n;
  	    if (elapse_n > 1000000000L) { kbytesec = ((double)totsnd / elapse_n * 1000000); start_n = now_n; totsnd = 0; 
  	                                fprintf(ptx.log,"kbytesec(%d)\n",(uint16_t)kbytesec); }
  	  } else start_n = now_n;
  	  totsnd += offset;
  
          if (seq == 65535)  seq = 1;  else seq++;
        }
      }
    }
  } else {

    init_rx_t prx;
    strcpy(prx.node,argv[argc - 1]);
    init_rx(&prx);

    double  kbytesec;
    bool lastpkt = false;
    uint8_t udp_in[PKT_SIZE_1_IN];
    uint8_t udp_out[UDP_SIZE];
    uint8_t *ppay;
    int8_t u8Antdbm, id;
    uint16_t len = 0, ret, u16HeaderLen, pos, seq, seqprev=1, offset = 0, datalen, totrcv = 0 ;
    uint32_t totfails = 0, totdrops = 0;
    uint32_t crc, crc_rx;
    uint64_t stp_n,now_n,elapse_n,start_n;
    struct timeval timeout;
    struct timespec now;
    ssize_t len_in, len_out;
    pay_hdr_t *phead;
    fd_set readset;

    for(;;) {
      FD_ZERO(&readset);
      FD_SET(prx.fd_raw, &readset);
      timeout.tv_sec = 1; timeout.tv_usec = 0;
      ret = select(1 + prx.fd_raw, &readset, NULL, NULL, &timeout);
      if(FD_ISSET(prx.fd_raw, &readset)) {
        if ( ret == 1 ) {
          len_in = read(prx.fd_raw, udp_in, PKT_SIZE_1_IN);
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
                len_out = sendto(prx.fd_out[id], udp_out, offset, 0, (struct sockaddr *)&(prx.addr_out[id]), sizeof(struct sockaddr));
                offset = 0; lastpkt = false;
      	        if ((seq>1) && (seqprev != seq-1)) totdrops ++;
      	        seqprev = seq;
              }
            }
          }
        }
      }
      clock_gettime( CLOCK_REALTIME, &now);
      now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
      if (seq != 1) { // Compute cyclic byte rate
        elapse_n = now_n - start_n;
        if (elapse_n > 1000000000L) { kbytesec = ((double)totrcv / elapse_n * 1000000); start_n = now_n; totrcv = 0; 
                                      fprintf(prx.log,"kbytesec(%d)fails(%d)drops(%d)dbm(%d)\n",(uint16_t)kbytesec,totfails,totdrops,u8Antdbm); }
      } else start_n = now_n;
      totrcv += len_out;
    }
  }
}
