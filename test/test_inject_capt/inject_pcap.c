#include <pcap.h>

#include "inject_capt.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint16_t param_pktnb  = 2000; 
  uint16_t param_pktlen = 1441;
  uint16_t param_ndelay = 800;
  uint8_t param_bitrate = 0x5; // 0x0, 0x3  -> 0x05

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t portId = 5;

  uint8_t buffer[PKT_SIZE_0], *ieee_hdr = ieee_hdr_data, *radiotap_hdr = uint8_taRadiotapHeader;
  uint8_t *ppay, *pu8 = buffer;
  pay_hdr_t *phead;

  printf("%d\n",DATA_SIZE);
  if (param_pktlen >  DATA_SIZE) exit(-1);

  struct timespec stp;
  uint64_t stp_n;
  int i, r, packet_size;
  uint16_t seq=1;

  pcap_t *ppcap = NULL;
  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';
  if(NULL == (ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf))) exit(-1);
  pcap_setnonblock(ppcap, 1, szErrbuf);

  memset(buffer, 0, sizeof (buffer));
  radiotap_hdr[27] = param_bitrate;
  memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
  ieee_hdr[9] = portId;  // Set in receiver address
  memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));

  uint16_t offset0 = sizeof(uint8_taRadiotapHeader)+sizeof(ieee_hdr_data);
  uint16_t offset1 = offset0 + sizeof(pay_hdr_t);

  packet_size = PKT_SIZE_0;

  for(i = 1; i <= param_pktnb; i++) {

    ppay = (pu8 + offset1);

    memset((char *)ppay,0,13);
    if (i == 1) strcpy((char *)ppay,"firstpkt-beg");
    else if (i == param_pktnb) strcpy((char *)ppay,"lastpkt-beg");

    phead = (pay_hdr_t *)(pu8 + offset0);
    phead->seq = seq;
    phead->len = param_pktlen;
       
    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));

    phead->stp_n = stp_n;

    r = pcap_inject(ppcap, buffer, packet_size);
    if (r != packet_size) exit(-1);

    printf("(%d)(%d)\n",seq,param_pktlen);
    printf("(%ld)\n",stp_n);
    printf("number of packets sent = %d\r", i);
    printf("\n");
    fflush(stdout);

    seq++;
    usleep(param_ndelay);
  }
}
