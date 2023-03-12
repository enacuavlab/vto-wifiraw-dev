#include <sys/time.h>
#include <sys/resource.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "radiotap_iter.h"

/*****************************************************************************/
#define MAX_PACKET_LENGTH 4192

/*****************************************************************************/
typedef struct {
  time_t last_update;
  uint32_t received_packet_cnt;
  uint32_t wrong_crc_cnt;
  int8_t current_signal_dbm;
} wifi_adapter_rx_status_t;

typedef struct {
  int n80211HeaderLength;
  pcap_t *ppcap;
  wifi_adapter_rx_status_t rx_status;
} process_packet_t;

typedef struct {
  uint32_t sequence_number;
} __attribute__((packed)) wifi_packet_header_t;


typedef struct  {
  int m_nChannel;
  int m_nChannelFlags;
  int m_nRate;
  int m_nAntenna;
  int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;

/*****************************************************************************/
int param_data_packets_per_block = 8;

/*****************************************************************************/
void process_payload(uint8_t *data, size_t data_len, int crc_correct) {

  wifi_packet_header_t *wph = (wifi_packet_header_t*)data;
  int block_num = wph->sequence_number / param_data_packets_per_block;

  data += sizeof(wifi_packet_header_t);
  data_len -= sizeof(wifi_packet_header_t);

  payload_header_t *ph = (payload_header_t*)data;
  data += sizeof(payload_header_t);

  write(STDOUT_FILENO, data, ph->data_length);
  fflush(stdout);
}


/*****************************************************************************/
void process_packet(process_packet_t *param) {

  struct pcap_pkthdr * ppcapPacketHeader = NULL;
  uint8_t payloadBuffer[MAX_PACKET_LENGTH];
  uint8_t *puint8Payload = payloadBuffer;

  int retval = pcap_next_ex(param->ppcap, &ppcapPacketHeader, (const u_char**)&puint8Payload);
  if (retval < 0) {
    if (strcmp("The interface went down",pcap_geterr(param->ppcap)) == 0) {
      fprintf(stderr, "rx: The interface went down\n");
      exit(9);
    } else {
      fprintf(stderr, "rx: %s\n", pcap_geterr(param->ppcap));
      exit(2);
    }
  }
  if (retval != 1) return;

  int u16HeaderLen = (puint8Payload[2] + (puint8Payload[3] << 8));
  if (ppcapPacketHeader->len < (u16HeaderLen + param->n80211HeaderLength)) return;

  int bytes = ppcapPacketHeader->len - (u16HeaderLen + param->n80211HeaderLength);
  if (bytes < 0) return;

  struct ieee80211_radiotap_iterator rti;
  if (ieee80211_radiotap_iterator_init(&rti,
                    (struct ieee80211_radiotap_header *)puint8Payload,
                    ppcapPacketHeader->len,
		    NULL) < 0) return;

  PENUMBRA_RADIOTAP_DATA prd;
  int n;
  while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {
    switch (rti.this_arg_index) {

      case IEEE80211_RADIOTAP_FLAGS:
        prd.m_nRadiotapFlags = *rti.this_arg;
        break;

      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        param->rx_status.current_signal_dbm = (int8_t)(*rti.this_arg);
        break;
    }
  }

  puint8Payload += u16HeaderLen + param->n80211HeaderLength;
  int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;
  if(!checksum_correct) param->rx_status.wrong_crc_cnt++;
  param->rx_status.received_packet_cnt++;
  param->rx_status.last_update = time(NULL);

  process_payload(puint8Payload, bytes, checksum_correct);
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  process_packet_t param;

  char szErrbuf[PCAP_ERRBUF_SIZE]; szErrbuf[0] = '\0';
  param.ppcap = pcap_open_live(argv[1], 1600, 0, -1, szErrbuf);
  if (param.ppcap == NULL) exit(-1);
  if(pcap_setnonblock(param.ppcap, 1, szErrbuf) < 0) exit(-1);

  char szProgram[512];
  int port = 0; /* 0-255 */
  int nLinkEncap = pcap_datalink(param.ppcap);
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
    param.n80211HeaderLength = 0x18;
    sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber
  } else exit(-1);

  struct bpf_program bpfprogram;
  if (pcap_compile(param.ppcap, &bpfprogram, szProgram, 1, 0) == -1) exit(-1);
  if (pcap_setfilter(param.ppcap, &bpfprogram) == -1) exit(-1);

  int fd = pcap_get_selectable_fd(param.ppcap);

  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);

    FD_SET(fd, &readset);

    int n = select(fd+1, &readset, NULL, NULL, NULL);

    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {
      process_packet(&param);
    }
  }
}
