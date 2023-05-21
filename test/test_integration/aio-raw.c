#include "aio-raw-com.h"

/*
sudo ./aio-raw 0 $node
sudo ./aio-raw 1 $node
*/

/*****************************************************************************/
int main(int argc, char *argv[]) {

  if ((argc==1)||(argc>3)) exit(-1);
  uint8_t role =atoi(argv[1]);
  if (!role) {
    init_tx_t ptx;
    strcpy(ptx.node,argv[argc - 1]);
    init_tx(&ptx);

    ssize_t len_in;
    uint16_t len = 0, offset = 0, seq = 1, len_tag, ret;
    uint8_t udp_in[UDP_SIZE];
  
    uint64_t stp_n,now_n,lastime_n,timeleft_n,elapse_n;
    struct timespec stp,timeleft;
    pay_hdr_t *phead;
  
    struct timeval timeout;
    fd_set readset;
 
    struct timespec now; 

    setpriority(PRIO_PROCESS, 0, -10);
  
    for(;;) {
      FD_ZERO(&readset);
      FD_SET(ptx.fd_in, &readset);
      timeout.tv_sec = 1; timeout.tv_usec = 0;
      ret = select(ptx.fd_in + 1, &readset, NULL, NULL, &timeout);
      if (ret > 0) {
        len_in = read(ptx.fd_in, udp_in + offset1, UDP_SIZE - offset1);
        offset = 0;
        while (len_in > 0) {
          if (len_in > DATA_SIZE) { len = DATA_SIZE; len_tag = len; }
          else { len = len_in; len_tag = len; (len_tag |= 1UL << 15); } // Set signed bit of unsigned length to signal  sequence end
        
          memcpy( udp_in + offset, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
	  ieee_hdr_data[9] = 5;
          memcpy( udp_in + offset + sizeof(uint8_taRadiotapHeader), ieee_hdr_data, sizeof(ieee_hdr_data));
          phead = (pay_hdr_t *)(udp_in + offset + offset0);
          phead->seq = seq;
          phead->len = len_tag;
          clock_gettime( CLOCK_MONOTONIC, &stp);
          stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
          phead->stp_n = stp_n;
             
          write(ptx.fd_out, udp_in + offset, len + offset1);
    
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
        if (seq == 65535)  seq = 1;  else seq++;

        clock_gettime( CLOCK_REALTIME, &now);
        now_n = (now.tv_nsec + (now.tv_sec * 1000000000L));
	if (seq == 1) start_n = now_n; // Compute cyclic byte rate
	else {
          elapse_n = now_n - start_n;
	  if (elapse_n > 1000000000L) { byterate = tosnd / elapse_n;  totsnd = 0; }
	  else totsnd += len_in;
	} 
      }
    }
  } else {
    init_rx_t prx;
    strcpy(prx.node,argv[argc - 1]);
    init_rx(&prx);

    uint32_t totfails = 0, totdrops = 0;
    uint32_t crc, crc_rx;
  
    struct timespec curr;
    ssize_t len_in, len_out;
    uint16_t len = 0, ret, u16HeaderLen, pos, seq, seqprev=1, offset = 0, datalen;
    uint8_t udp_in[PKT_SIZE_1_IN];
    uint8_t udp_out[UDP_SIZE];
    uint8_t *ppay;
    bool lastpkt = false;
  
    uint64_t stp_n;
    pay_hdr_t *phead;
  
    fd_set readset;
    for(;;) {
      FD_ZERO(&readset);
      FD_SET(prx.fd_in, &readset);
      ret = select(prx.fd_in + 1, &readset, NULL, NULL, NULL);
      if(FD_ISSET(prx.fd_in, &readset)) {  
        if ( ret == 1 ) {
          len_in = read(prx.fd_in, udp_in, PKT_SIZE_1_IN);
          if (len_in > 0) {
  
            clock_gettime( CLOCK_MONOTONIC, &curr);
            u16HeaderLen = (udp_in[2] + (udp_in[3] << 8)); // variable radiotap header size
            pos = u16HeaderLen + sizeof(ieee_hdr_data);
   
    	    phead = (pay_hdr_t *)(udp_in + pos);
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
  								
            if (~crc != crc_rx) {
  	      totfails ++;
              printf("fails (%d)\n",totfails);
  	    } else {
    	      ppay = (udp_in + pos + sizeof(pay_hdr_t));
              memcpy(udp_out + offset , ppay, len);
    	      offset += len;
    
              if (lastpkt)  {
                len_out = sendto(prx.fd_out, udp_out, offset, 0, (struct sockaddr *)&(prx.addr_out), sizeof(struct sockaddr));
                offset = 0; lastpkt = false;
  	        if ((seq>1) && (seqprev != seq-1)) {
  	          totdrops ++;
                  printf("drops (%d)(%d)\n",totdrops,seq);
  	        }
  	        seqprev = seq;
              }
            }
  	  }
        }
      }
    }
  }
}
