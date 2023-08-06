#include "wfb.h"

#define GET_TEMPERATURE fflush(tempstream);fseek(tempstream,0,SEEK_SET);fread(&strtmp,1,sizeof(strtmp),tempstream);wfb.temp = atoi(strtmp);

/*****************************************************************************/
int main(int argc, char *argv[]) {

  init_t param;
  param.node = argv[1];
  wfb_init(&param);

  FILE *tempstream=fopen("/sys/class/thermal/thermal_zone0/temp","rb");

  wfb_t wfb;
  memset(&wfb,0,sizeof(wfb_t));

#ifdef RAW
  uint16_t datalen, radiotapvar;
  int8_t offset;
  uint32_t crc, crc_rx;
#endif // RAW
#if ROLE
  bool wfbtosend=false;
  uint64_t sto_n=0;
  struct timeval timeout;
#endif // ROLE
  char strtmp[6];
  fd_set readset;
  struct timespec stp;
  uint8_t onlinebuff[FD_NB][ONLINE_SIZE],*ptr;
  bool crcok=false,datatosend=false;
  uint8_t id;
  uint16_t ret,seq,seq_prev,seq_out=0,dst,src;
  uint64_t stp_n;
  ssize_t len,lensum;
  ssize_t lentab[FD_NB];
  memset(&lentab,0, FD_NB*sizeof(ssize_t));
  for(;;) {
    FD_ZERO(&readset);
    readset = param.readset;
#if ROLE
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(param.maxfd + 1, &readset, NULL, NULL, &timeout);
#else
    ret = select(param.maxfd + 1, &readset, NULL, NULL, NULL);
#endif // ROLE 
    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
#if ROLE
    if (sto_n == 0) sto_n = stp_n;
    else if ((stp_n - sto_n) > 1000000000L) { sto_n = stp_n; wfbtosend=true; }
#endif  // ROLE
    for (int cpt = RAW_FD; cpt < FD_NB; cpt++) {
#if ROLE
      if (((ret==0)&&(cpt==WFB_FD)&&wfbtosend) || (ret>0)) {
#else
      if  ((ret>0)&&(param.fd[cpt]!=0)&&FD_ISSET(param.fd[cpt], &readset)) {
#endif // ROLE
        if ((cpt==RAW_FD)&&FD_ISSET(param.fd[cpt], &readset)) {
          len = read(param.fd[RAW_FD], &onlinebuff[cpt][0], ONLINE_SIZE);
#ifdef RAW
          radiotapvar = (onlinebuff[cpt][2] + (onlinebuff[cpt][3] << 8)); // get variable radiotap header size
          offset = radiotapvar + sizeof(ieeehdr);
          wfb.antdbm = onlinebuff[cpt][31];
          datalen = sizeof(ieeehdr) + sizeof(payhdr_t) + ((payhdr_t *)(onlinebuff[cpt] + offset))->len;
          const uint8_t *s = &onlinebuff[cpt][radiotapvar];  // compute CRC32 after radiotap header
          crc=0xFFFFFFFF;
          for(uint32_t i=0;i<datalen;i++) {
            uint8_t ch=s[i];
            uint32_t t=(ch^crc)&0xFF;
            crc=(crc>>8)^crc32_table[t];
          }
          memcpy(&crc_rx, &onlinebuff[cpt][len - 4], sizeof(crc_rx)); // CRC32 : last four bytes
          if (~crc != crc_rx) {wfb.fails ++;crcok=false;}
          else crcok = true;
          ptr=&onlinebuff[cpt][0]+offset;
#else
          ptr=&onlinebuff[cpt][0];
          crcok = true;
#endif // RAW
          if (crcok) {
            stp_n = ((payhdr_t *)ptr)->stp_n;
            seq = ((payhdr_t *)ptr)->seq;
            if ((seq>1) && (seq_prev != seq-1)) wfb.drops ++;
            seq_prev = seq;
            lensum = ((payhdr_t *)ptr)->len;
            ptr+=sizeof(payhdr_t);
	    while (lensum>0) {
              id = ((subpayhdr_t *)ptr)->id;
              len = ((subpayhdr_t *)ptr)->len;
	      lensum -= (len + sizeof(subpayhdr_t));
              ptr+=sizeof(subpayhdr_t);
#if ROLE
              write(param.fd[id], ptr, len);
#else
	      if (id==TUN_FD)  write(param.fd[TUN_FD], ptr, len);
              len = sendto(param.fd[id],ptr,len,0,(struct sockaddr *)&(param.addr_out[id]), sizeof(struct sockaddr));
              if (id==WFB_FD) {
                printf("BOARD  (%d)(%d)(%d)(%d)(%d)(%d)\n",((wfb_t *)ptr)->temp,((wfb_t *)ptr)->antdbm,((wfb_t *)ptr)->fails,
				                           ((wfb_t *)ptr)->drops,((wfb_t *)ptr)->sent,((wfb_t *)ptr)->rate);
                GET_TEMPERATURE;
                printf("GROUND (%d)(%d)(%d)(%d)(%d)(%d)\n",wfb.temp,wfb.antdbm,wfb.fails, wfb.drops,wfb.sent, wfb.rate);
              }
#endif // ROLE
              ptr+=len;
	    }
          }
        } else {
          len=0;
#if ROLE
	  if ((cpt==WFB_FD)&&wfbtosend ) {
            GET_TEMPERATURE;
            memcpy(&onlinebuff[cpt][0]+(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t), &wfb, sizeof(wfb_t));
	    len = sizeof(wfb_t);
	    wfbtosend=false;

            printf("(%d)(%d)(%d(%d(%d)(%d)\n",wfb.temp,wfb.antdbm,wfb.fails,wfb.drops,wfb.sent,wfb.rate);
	  } 
#endif // ROLE
	  if ((param.fd[cpt]!=0)&&FD_ISSET(param.fd[cpt], &readset)) len = read(param.fd[cpt], 
	    &onlinebuff[cpt][0]+(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t),ONLINE_SIZE-(param.offsetraw)-sizeof(payhdr_t)-sizeof(subpayhdr_t));

	  if (len>0) {
            ptr=&onlinebuff[cpt][0]+(param.offsetraw);
            (((payhdr_t *)ptr)->len) = len + sizeof(subpayhdr_t);;
            ptr+=sizeof(payhdr_t);
            (((subpayhdr_t *)ptr)->id) = cpt;
            (((subpayhdr_t *)ptr)->len) = len;
            lentab[cpt] = len;
    	    datatosend=true;
	  }
#ifdef RAW
#if ROLE == 2   
          if ((cpt==TEL_FD)&&FD_ISSET(param.fd[cpt], &readset)) sendto(param.fd_teeuart,&onlinebuff[cpt][0]+(param.offsetraw)+sizeof(payhdr_t)+sizeof(subpayhdr_t),len,0,
			                                               (struct sockaddr *)&(param.addr_out[cpt]), sizeof(struct sockaddr));
#endif // ROLE == 2
#endif // RAW
	}
      }
    }
    if(datatosend) {
      datatosend=false;
      for (int cpt = (RAW_FD+1); cpt < FD_NB; cpt++) {
        if (lentab[cpt]!=0) {
          for (int i=cpt+1;i<FD_NB;i++) {
            if (lentab[i]!=0) {
              if (lentab[cpt]+lentab[i] < (ONLINE_MTU-sizeof(subpayhdr_t))) { // join packets to send whithin payload size 
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
            len = (((payhdr_t *)ptr)->len);
#ifdef RAW
	    memcpy(&onlinebuff[cpt][0],radiotaphdr,sizeof(radiotaphdr));
            memcpy(&onlinebuff[cpt][0]+sizeof(radiotaphdr),ieeehdr,sizeof(ieeehdr));
            len = write(param.fd[RAW_FD],&onlinebuff[cpt][0],(param.offsetraw)+sizeof(payhdr_t)+len);
#else 
            len = sendto(param.fd[RAW_FD],&onlinebuff[cpt][0]+(param.offsetraw),sizeof(payhdr_t)+len,0,(struct sockaddr *)&(param.addr_out[0]), sizeof(struct sockaddr));
#endif // RAW

            lentab[cpt]=0;
            seq_out++;
  	    wfb.sent=seq_out;
  	  }
        }
      }
    }
  }
}
