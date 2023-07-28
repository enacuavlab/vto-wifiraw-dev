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
  uint8_t onlinebuff[ONLINE_SIZE],*ptr;
  bool crcok = false;
  ssize_t len;
  uint8_t id;
  uint16_t ret,seq,seq_prev,seq_out=0;
  uint32_t fails=0,drops=0;
  uint64_t stp_n;
  for(;;) {
    FD_ZERO(&readset);
    readset = param.readset;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(param.maxfd + 1, &readset, NULL, NULL, &timeout);
    if (ret >0) {
      for (int cpt = 0; cpt < FD_NB; cpt++) {
        if(FD_ISSET(param.fd[cpt], &readset)) {
          if (cpt == 0) {
            len = read(param.fd[0], onlinebuff, ONLINE_SIZE);
#ifdef RAW	
            radiotapvar = (onlinebuff[2] + (onlinebuff[3] << 8)); // get variable radiotap header size
            offset = radiotapvar + sizeof(ieeehdr);
            antdbm = onlinebuff[31];
            datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + ((payhdr_t *)(onlinebuff + offset))->len;
            const uint8_t *s = &onlinebuff[radiotapvar];  // compute CRC32 after radiotap header
            crc=0xFFFFFFFF;
            for(uint32_t i=0;i<datalen;i++) {
              uint8_t ch=s[i];
              uint32_t t=(ch^crc)&0xFF;
              crc=(crc>>8)^crc32_table[t];
            }
            memcpy(&crc_rx, &onlinebuff[len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
            if (~crc != crc_rx) {fails ++;crcok=false;}
            else crcok = true;
            ptr=onlinebuff+offset;
#else
            ptr=onlinebuff;
            crcok = true;
#endif // RAW

            if (crcok) {      
      
              seq = ((payhdr_t *)ptr)->seq;
              len = ((payhdr_t *)ptr)->len;
              stp_n = ((payhdr_t *)ptr)->stp_n;
              ptr+=sizeof(payhdr_t);
              id = ((subpayhdr_t *)ptr)->id;
              len = ((subpayhdr_t *)ptr)->len;
              ptr+=sizeof(subpayhdr_t);
              write(param.fd[1], ptr, len);
      
              if ((seq>1) && (seq_prev != seq-1)) drops ++;
              seq_prev = seq;
            }
	  } else {

            ptr = onlinebuff+(param.offsetraw);

            len = read(param.fd[1], ptr+sizeof(payhdr_t)+sizeof(subpayhdr_t), ONLINE_SIZE-(param.offsetraw)-sizeof(payhdr_t)-sizeof(subpayhdr_t));
	    clock_gettime( CLOCK_MONOTONIC, &stp);
            stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

            (((payhdr_t *)ptr)->seq) = seq_out;
            (((payhdr_t *)ptr)->len) = len + sizeof(subpayhdr_t);;
            (((payhdr_t *)ptr)->stp_n) = stp_n;

            ptr += sizeof(payhdr_t);
            (((subpayhdr_t *)ptr)->id) = 1;
            (((subpayhdr_t *)ptr)->len) = len;
#ifdef RAW                 
            memcpy(onlinebuff,radiotaphdr,sizeof(radiotaphdr));
            memcpy(onlinebuff+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
	    len = write(param.fd[0],onlinebuff,(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t)+len);
#else
	    len = sendto(param.fd[0],onlinebuff+(param.offsetraw),sizeof(payhdr_t)+sizeof(subpayhdr_t)+len,0,(struct sockaddr *)&(param.addr_out[0]), sizeof(struct sockaddr));
#endif // RAW
	    seq_out++;
	  }
	}
      }
    }
  }
}
