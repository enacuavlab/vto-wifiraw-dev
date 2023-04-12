#include "test_inject.h"

#define PKT_SIZE_MAX 2311

#define PKT_SIZE PKT_SIZE_MAX
//#define PKT_SIZE 1510

#define PKT_DATA (PKT_SIZE - sizeof(radiotap_hdr) - sizeof(wifi_hdr) - sizeof(llc_hdr) - sizeof(pay_hdr_t))

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  uint8_t buf[PKT_SIZE];
  uint8_t *pu8 = buf;
  uint8_t portId = 5;

  memcpy(buf, radiotap_hdr, sizeof(radiotap_hdr));
  pu8 += sizeof(radiotap_hdr);
  memcpy(pu8, wifi_hdr, sizeof(wifi_hdr));
  pu8[5] = portId;
  pu8 += sizeof(wifi_hdr);
  memcpy(pu8, llc_hdr, sizeof(llc_hdr));
  pu8 += sizeof(llc_hdr);
  uint8_t hdr_len = pu8 - buf;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *ppcap = pcap_create(argv[1], errbuf);

  if (pcap_set_snaplen(ppcap, 4096) !=0) exit(-1);
  if (pcap_set_promisc(ppcap, 1) != 0) exit(-1);
  if (pcap_set_timeout(ppcap, -1) !=0) exit(-1);
  if (pcap_set_immediate_mode(ppcap, 1) != 0) exit(-1);
  if (pcap_activate(ppcap) !=0) exit(-1);

  uint64_t stp_n;
  uint16_t data_len, trans_len, ret, seq = 0;
  struct timespec stp, wait_n;
  wait_n.tv_sec=0;
  wait_n.tv_nsec=1000000; // KO 
//  wait_n.tv_nsec=10000000; // OK

  data_len = PKT_DATA;
  trans_len = hdr_len + sizeof(pay_hdr_t) + data_len;

  for (int i=0;i<820;i++) {

    nanosleep(&wait_n,&wait_n); 
    (((pay_hdr_t *)pu8)->seq) = seq;
    (((pay_hdr_t *)pu8)->len) = data_len;
  
    clock_gettime( CLOCK_MONOTONIC, &stp);
    stp_n = (stp.tv_nsec + (stp.tv_sec * 1000000000L));
  
    (((pay_hdr_t *)pu8)->stp_n) = stp_n;
  
    ret = pcap_inject(ppcap, buf, trans_len);
    if (ret <= 0) {
      printf("pcap_inject failure (%s)\n",pcap_geterr(ppcap));
      exit(-1);
    }
    printf("(%d)(%d)(%d)\n",seq,trans_len,ret);
    printf("(%ld)\n",stp_n);
    printf("-----------------------------\n");

    seq++;
  }
}
