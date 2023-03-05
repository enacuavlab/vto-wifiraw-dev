#include <sys/time.h>
#include <sys/resource.h>

#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "radiotap_iter.h"

#define MAX_PACKET_LENGTH 4192


/*****************************************************************************/
int param_data_packets_per_block = 8;


/*****************************************************************************/
typedef struct {
  int n80211HeaderLength;
  int selectable_fd;
  pcap_t *ppcap;
} monitor_interface_t;


typedef struct {
  time_t last_update;
  uint32_t received_packet_cnt;
  uint32_t wrong_crc_cnt;
  int8_t current_signal_dbm;
} wifi_adapter_rx_status_t;


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


/*****************************************************************************/
void init(char *name, monitor_interface_t *interface) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE];
  szErrbuf[0] = '\0';

  interface->ppcap = pcap_open_live(name, 1600, 0, -1, szErrbuf);
  if (interface->ppcap == NULL) {
    fprintf(stderr, "Unable to open %s: %s\n", name, szErrbuf);
    exit(1);
  }

  if(pcap_setnonblock(interface->ppcap, 1, szErrbuf) < 0) {
    fprintf(stderr, "Error setting %s to nonblocking mode: %s\n", name, szErrbuf);
  }

  char szProgram[512];
  int port = 0; /* 0-255 */
  int nLinkEncap = pcap_datalink(interface->ppcap);
  if (nLinkEncap == DLT_IEEE802_11_RADIO) {
    interface->n80211HeaderLength = 0x18;
    sprintf(szProgram, "ether[0x00:2] == 0x08bf && ether[0x04:2] == 0xff%.2x", port); // match on frametype, 1st byte of mac (ff) and portnumber
  } else {
    fprintf(stderr, "ERROR: unknown encapsulation on %s! check if monitor mode is supported and enabled\n", name);
    exit(1);
  }

  struct bpf_program bpfprogram;
  if (pcap_compile(interface->ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
    fprintf(stderr, "%s\n", szProgram);
    fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
    exit(1);
  } else {
    if (pcap_setfilter(interface->ppcap, &bpfprogram) == -1) {
      fprintf(stderr, "%s\n", szProgram);
      fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
    }
    pcap_freecode(&bpfprogram);
  }

  interface->selectable_fd = pcap_get_selectable_fd(interface->ppcap);
}

/*****************************************************************************/
void process_payload(int *seq,uint8_t *data, size_t data_len, int crc_correct) {

  wifi_packet_header_t *wph;

  wph = (wifi_packet_header_t*)data;
  data += sizeof(wifi_packet_header_t);
  data_len -= sizeof(wifi_packet_header_t);

//  printf("PKT %d %ld\n",*seq,data_len);

  (*seq)++;
  int block_num = wph->sequence_number / param_data_packets_per_block;
//  printf("rec %x blk %x crc %d len %ld\n", wph->sequence_number, block_num, crc_correct, data_len);

//  int param_packet_length = 1024;

  data += 4;
  data_len -= 4;
  write(STDOUT_FILENO, data, data_len);


  fflush(stdout);
}


/*****************************************************************************/
void process_packet(int *seq,monitor_interface_t *interface,wifi_adapter_rx_status_t *rx_status) {

  struct pcap_pkthdr * ppcapPacketHeader = NULL;
  uint8_t payloadBuffer[MAX_PACKET_LENGTH];
  uint8_t *puint8Payload = payloadBuffer;

  int retval = pcap_next_ex(interface->ppcap, &ppcapPacketHeader, (const u_char**)&puint8Payload);
  if (retval < 0) {
    if (strcmp("The interface went down",pcap_geterr(interface->ppcap)) == 0) {
      fprintf(stderr, "rx: The interface went down\n");
      exit(9);
    } else {
      fprintf(stderr, "rx: %s\n", pcap_geterr(interface->ppcap));
      exit(2);
    }
  }
  if (retval != 1) return;

  int u16HeaderLen = (puint8Payload[2] + (puint8Payload[3] << 8));
  if (ppcapPacketHeader->len < (u16HeaderLen + interface->n80211HeaderLength)) return;

  int bytes = ppcapPacketHeader->len - (u16HeaderLen + interface->n80211HeaderLength);
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
        rx_status->current_signal_dbm = (int8_t)(*rti.this_arg);
        break;
    }
  }

  puint8Payload += u16HeaderLen + interface->n80211HeaderLength;
  int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;
  if(!checksum_correct) rx_status->wrong_crc_cnt++;
  rx_status->received_packet_cnt++;
  rx_status->last_update = time(NULL);

  process_payload(seq,puint8Payload, bytes, checksum_correct);
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  monitor_interface_t interface;
  wifi_adapter_rx_status_t rx_status;

  init(argv[1], &interface);

  int seq=0;
  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);
    FD_SET(interface.selectable_fd, &readset);

    int n = select(interface.selectable_fd+1, &readset, NULL, NULL, NULL);

    if(n == 0) break;
    if(FD_ISSET(interface.selectable_fd, &readset)) {
      printf("INBOUND\n");fflush(stdout);
      process_packet(&seq,&interface, &rx_status);
    }
  }
}


