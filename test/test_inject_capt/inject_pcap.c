#include <pcap.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint16_t param_pktnb  = 2000; 
  uint16_t param_pktlen = 1466;
  uint16_t param_ndelay = 400;

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t portId = 5;

  uint8_t buffer[PKT_SIZE], *ieee_hdr = ieee_hdr_data;
  uint8_t *pu8 = buffer;

  printf("%ld\n",DATA_SIZE);
  if (param_pktlen >  DATA_SIZE) exit(-1);

  struct timespec stp;
  uint64_t stp_n;
  int i, r, packet_size;
  uint16_t seq=0;

  pcap_t *ppcap = NULL;
  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';
  if(NULL == (ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf))) exit(-1);
  pcap_setnonblock(ppcap, 1, szErrbuf);

  memset(buffer, 0, sizeof (buffer));
  memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  pu8 += sizeof (uint8_taRadiotapHeader);


  ieee_hdr[9] = portId;
  memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));
  pu8 += sizeof (ieee_hdr_data);

  packet_size = PKT_SIZE;

  for(i = 1; i <= param_pktnb; i++) {

    (((pay_hdr_t *)pu8)->seq) = seq;
    (((pay_hdr_t *)pu8)->len) = param_pktlen;
       
    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
       
    (((pay_hdr_t *)pu8)->stp_n) = stp_n;

    r = pcap_inject(ppcap, buffer, packet_size);
    if (r != packet_size) exit(-1);

    printf("(%d)(%d)\n",seq,param_pktlen);
    printf("(%ld)\n",stp_n);

    printf("number of packets sent = %d\r", i);
    fflush(stdout);

    seq++;

    usleep(param_ndelay);

    printf("\n");
  }
}
