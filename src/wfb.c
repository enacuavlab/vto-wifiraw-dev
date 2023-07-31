#include "wfb.h"


/*****************************************************************************/
int main(int argc, char *argv[]) {

  init_t param;
  param.node = argv[1];
  wfb_init(&param);

#ifdef RAW	
  uint16_t datalen, radiotapvar;
  int8_t antdbm,offset;
  uint32_t crc, crc_rx;
#endif // RAW 

  fd_set readset;
  struct timespec stp;
  struct timeval timeout;
  uint8_t onlinebuff[FD_NB][ONLINE_SIZE],*ptr;
  bool crcok=false,datatosend=false;;
  uint8_t id;
  uint16_t ret,seq,seq_prev,seq_out=0,dst,src;
  uint32_t fails=0,drops=0;
  uint64_t stp_n;
  ssize_t len,lensum;
  ssize_t lentab[FD_NB];
  memset(&lentab,0, FD_NB*sizeof(ssize_t));
  for(;;) {
    FD_ZERO(&readset);
    readset = param.readset;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(param.maxfd + 1, &readset, NULL, NULL, &timeout);
    if (ret >0) {
      for (int cpt = 0; cpt < FD_NB; cpt++) {
        if(FD_ISSET(param.fd[cpt], &readset)) {
          if (cpt == 0) {
            len = read(param.fd[0], &onlinebuff[cpt][0], ONLINE_SIZE);
#ifdef RAW	
            radiotapvar = (onlinebuff[cpt][2] + (onlinebuff[cpt][3] << 8)); // get variable radiotap header size
            offset = radiotapvar + sizeof(ieeehdr);
            antdbm = onlinebuff[cpt][31];
            datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + ((payhdr_t *)(onlinebuff[cpt] + offset))->len;
            const uint8_t *s = &onlinebuff[cpt][radiotapvar];  // compute CRC32 after radiotap header
            crc=0xFFFFFFFF;
            for(uint32_t i=0;i<datalen;i++) {
              uint8_t ch=s[i];
              uint32_t t=(ch^crc)&0xFF;
              crc=(crc>>8)^crc32_table[t];
            }
            memcpy(&crc_rx, &onlinebuff[cpt][len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
            if (~crc != crc_rx) {fails ++;crcok=false;}
            else crcok = true;
            ptr=&onlinebuff[cpt][0]+offset;
#else
            ptr=&onlinebuff[cpt][0];
            crcok = true;
#endif // RAW
            if (crcok) {      
              stp_n = ((payhdr_t *)ptr)->stp_n;
              seq = ((payhdr_t *)ptr)->seq;
              if ((seq>1) && (seq_prev != seq-1)) drops ++;
              seq_prev = seq;
              lensum = ((payhdr_t *)ptr)->len;
	      while (lensum>0) {
                ptr+=sizeof(payhdr_t);
                id = ((subpayhdr_t *)ptr)->id;
                len = ((subpayhdr_t *)ptr)->len;
		lensum -= (len + sizeof(subpayhdr_t));
                ptr+=sizeof(subpayhdr_t);
#if ROLE
                write(param.fd[id], ptr, len);
#else
	        if (id==1)  write(param.fd[1], ptr, len);
	        len = sendto(param.fd[id],ptr,len,0,(struct sockaddr *)&(param.addr_out[id]), sizeof(struct sockaddr));
#endif // ROLE
	      }
            }
	  } else {
            len = read(param.fd[cpt], &onlinebuff[cpt][0]+(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t),
			              ONLINE_SIZE-(param.offsetraw)-sizeof(payhdr_t)-sizeof(subpayhdr_t));
            ptr=&onlinebuff[cpt][0]+(param.offsetraw);
            (((payhdr_t *)ptr)->len) = len + sizeof(subpayhdr_t);;
            ptr+=sizeof(payhdr_t);
            (((subpayhdr_t *)ptr)->id) = cpt;
            (((subpayhdr_t *)ptr)->len) = len;
            lentab[cpt] = len;
	    datatosend=true;
	  }
	}
      }
      if(datatosend) {
	datatosend=false;
	clock_gettime( CLOCK_MONOTONIC, &stp);
        stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
        for (int cpt = 1; cpt < FD_NB; cpt++) {
	  if (lentab[cpt]!=0) {
	    for (int i=cpt+1;i<FD_NB;i++) {
	      if (lentab[i]!=0) {
                if (lentab[cpt]+lentab[i] < ONLINE_MTU) { // join packets to send whithin payload size 
		  if (lentab[cpt]>lentab[i]) { dst=cpt; src=i; } else { dst=i; src=cpt; }
		  memcpy(&onlinebuff[dst][0]+(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t)+lentab[dst],
                         &onlinebuff[src][0]+(param.offsetraw)+sizeof(payhdr_t), 
			 sizeof(subpayhdr_t)+lentab[src]);
		  ptr=&onlinebuff[dst][0]+(param.offsetraw);
		  (((payhdr_t *)ptr)->len)  += (lentab[src]+sizeof(subpayhdr_t));
		  lentab[src]=0;
		} 
	      }
	    }

	    if (lentab[cpt]!=0) { // make sure current packet have not been joined
              ptr = &onlinebuff[cpt][0]+(param.offsetraw);
              (((payhdr_t *)ptr)->seq) = seq_out;
              (((payhdr_t *)ptr)->stp_n) = stp_n;
  #ifdef RAW                 
              memcpy(&onlinebuff[cpt][0],radiotaphdr,sizeof(radiotaphdr));
              memcpy(&onlinebuff[cpt][0]+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
      	      len = write(param.fd[0],&onlinebuff[cpt][0],(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t)+len);
  #else
      	      len = sendto(param.fd[0],&onlinebuff[cpt][0]+(param.offsetraw),sizeof(payhdr_t)+sizeof(subpayhdr_t)+len,0,(struct sockaddr *)&(param.addr_out[0]), sizeof(struct sockaddr));
  #endif // RAW
              lentab[cpt]=0;
      	      seq_out++;
	    }
	  }
	}
      }
    }
  }
}
