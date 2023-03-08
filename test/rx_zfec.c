#include <sys/time.h>
#include <sys/resource.h>

#include <limits.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fec.h"
#include "radiotap_iter.h"


/*****************************************************************************/
int param_data_packets_per_block = 8;
int param_fec_packets_per_block = 8;
int param_block_buffers = 1;
int param_packet_length = 1450;

int max_block_num = -1;

/*****************************************************************************/
typedef struct {
  int valid;
  int crc_correct;
  size_t len; 
  uint8_t *data;
} packet_buffer_t;


typedef struct {
  fec_t* fec_p;
  const unsigned char **inpkts;
  unsigned char **outpkts;
  unsigned *indexes;
  size_t sz; 
  packet_buffer_t *data_pkgs;
  packet_buffer_t *fec_pkgs;
  uint8_t *data_blocks;
  uint8_t *fec_blocks;
} myfec_t;


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
  uint32_t received_block_cnt;
  uint32_t damaged_block_cnt;
  uint32_t lost_packet_cnt;
  uint32_t tx_restart_cnt;
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


typedef struct {
    uint32_t data_length;
} __attribute__((packed)) payload_header_t;


typedef struct {
  int block_num;
  packet_buffer_t *packet_buffer_list;
} block_buffer_t;


/*****************************************************************************/  
#define MAX_USER_PACKET_LENGTH 1450
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32
#define MAX_PACKET_LENGTH 4192


/*****************************************************************************/
void init(char *name, monitor_interface_t *interface, myfec_t *myfec) {

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
 
  if (param_fec_packets_per_block) {
    int i; 
    myfec->sz = MAX_USER_PACKET_LENGTH;

    const unsigned char *inpkts[param_fec_packets_per_block];
    for (i=0;i<param_fec_packets_per_block;i++) inpkts[i]=malloc(myfec->sz);
    unsigned char *outpkts[param_fec_packets_per_block];
    for (i=0;i<param_fec_packets_per_block;i++) outpkts[i]=malloc(myfec->sz);
    unsigned indexes[] = {4, 7};
    packet_buffer_t *data_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
    packet_buffer_t *fec_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
    uint8_t *data_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
    uint8_t *fec_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
 
    myfec->fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block); 
    myfec->inpkts = inpkts;
    myfec->outpkts = outpkts;
    myfec->indexes = indexes;
    myfec->data_pkgs = data_pkgs;
    myfec->fec_pkgs = fec_pkgs;
    myfec->data_blocks = data_blocks;
    myfec->fec_blocks = fec_blocks;
  }
}

/*****************************************************************************/
void process_payload(myfec_t *myfec,int *seq,uint8_t *data, size_t data_len, int crc_correct, block_buffer_t *block_buffer_list ,wifi_adapter_rx_status_t *rx_status) {
  wifi_packet_header_t *wph;

  int packet_num;
  int i;

  wph = (wifi_packet_header_t*)data;
  data += sizeof(wifi_packet_header_t);
  data_len -= sizeof(wifi_packet_header_t);

  (*seq)++;
  int block_num = wph->sequence_number / param_data_packets_per_block;
//  printf("rec %x blk %x crc %d len %ld\n", wph->sequence_number, block_num, crc_correct, data_len);

  payload_header_t *ph = (payload_header_t*)data;
  data += sizeof(payload_header_t);

  int tx_restart = (block_num + 128*param_block_buffers < max_block_num);
  if((block_num > max_block_num || tx_restart) && crc_correct) {
    if(tx_restart) {
      rx_status->tx_restart_cnt++;
//      printf("TX re-start detected\n");
//      block_buffer_list_reset(block_buffer_list, param_block_buffers, param_data_packets_per_block + param_fec_packets_per_block);
    }

    //first, find the minimum block num in the buffers list. this will be the block that we replace
    int min_block_num = INT_MAX;
    int min_block_num_idx;
    for(i=0; i<param_block_buffers; ++i) {
      if(block_buffer_list[i].block_num < min_block_num) {
        min_block_num = block_buffer_list[i].block_num;
        min_block_num_idx = i;
      }
    }

//    printf("removing block %x at index %i for block %x\n", min_block_num, min_block_num_idx, block_num);

    packet_buffer_t *packet_buffer_list = block_buffer_list[min_block_num_idx].packet_buffer_list;
    int last_block_num = block_buffer_list[min_block_num_idx].block_num;

    if(last_block_num != -1) {
      rx_status->received_block_cnt++;

      // split data and fec and count damaged
      int datas_missing = 0, datas_corrupt = 0, fecs_missing = 0,fecs_corrupt = 0;
      int di=0,fi=0,i=0;

      i = 0;
      while(di < param_data_packets_per_block || fi < param_fec_packets_per_block) {
        if(di < param_data_packets_per_block) {
          myfec->data_pkgs[di] = packet_buffer_list[i];
	  i++;
          myfec->data_blocks[di] = myfec->data_pkgs[di].data;
          if(!myfec->data_pkgs[di].valid)
            datas_missing++;

          if(myfec->data_pkgs[di].valid && !myfec->data_pkgs[di].crc_correct)
            datas_corrupt++;
          di++;
        }

        if(fi < param_fec_packets_per_block) {
          myfec->fec_pkgs[fi] = packet_buffer_list[i];
	  i++;
          if(!myfec->fec_pkgs[fi].valid)
            fecs_missing++;
          if(myfec->fec_pkgs[fi].valid && !myfec->fec_pkgs[fi].crc_correct)
             fecs_corrupt++;

          fi++;
        }
      }

      const int good_fecs_c = param_fec_packets_per_block - fecs_missing - fecs_corrupt;
      const int datas_missing_c = datas_missing;
      const int datas_corrupt_c = datas_corrupt;
      const int fecs_missing_c = fecs_missing;
      const int fecs_corrupt_c = fecs_corrupt;

      int packets_lost_in_block = 0;
      int good_fecs = good_fecs_c;
      //the following three fields are infos for fec_decode
      unsigned int fec_block_nos[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
      unsigned int erased_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
      unsigned int nr_fec_blocks = 0;

      if(datas_missing_c + fecs_missing_c > 0) {
        packets_lost_in_block = (datas_missing_c + fecs_missing_c);
        rx_status->lost_packet_cnt = rx_status->lost_packet_cnt + packets_lost_in_block;
      }

      rx_status->received_packet_cnt = rx_status->received_packet_cnt + param_data_packets_per_block + param_fec_packets_per_block - packets_lost_in_block;
/*
      if(datas_missing_c + datas_corrupt_c > good_fecs_c) {
        int x;
        for(x=0;x<param_data_packets_per_block; ++x) {
          if(myfec->data_pkgs[x].valid) {
            if(myfec->data_pkgs[x].crc_correct)
              printf("v");
            else
              printf("c");
            }
            else
              printf("m");
        }
        printf(" ");
        for(x=0;x<param_fec_packets_per_block; ++x) {
          if(myfec->fec_pkgs[x].valid) {
            if(myfec->fec_pkgs[x].crc_correct)
              printf("v");
            else
              printf("c");
            }
            else
              printf("m");
	} 
        printf("\n");
      }
*/
      fi = 0;
      di = 0;

      //look for missing DATA and replace them with good FECs
      while(di < param_data_packets_per_block && fi < param_fec_packets_per_block) {
        //if this data is fine we go to the next
        if(myfec->data_pkgs[di].valid && myfec->data_pkgs[di].crc_correct) {
           di++;
           continue;
        }

        //if this DATA is corrupt and there are less good fecs than missing datas we cannot do anything for this data
        if(myfec->data_pkgs[di].valid && !myfec->data_pkgs[di].crc_correct && good_fecs <= datas_missing) {
          di++;
          continue;
        }

        //if this FEC is not received we go on to the next
        if(!myfec->fec_pkgs[fi].valid) {
          fi++;
          continue;
        }

        //if this FEC is corrupted and there are more lost packages than good fecs we should replace this DATA even with this corrupted FEC
        if(!myfec->fec_pkgs[fi].crc_correct && datas_missing > good_fecs) {
          fi++;
          continue;
	} 


        if(!myfec->data_pkgs[di].valid)
           datas_missing--;
        else if(!myfec->data_pkgs[di].crc_correct)
           datas_corrupt--;

        if(myfec->fec_pkgs[fi].crc_correct)
          good_fecs--;

        //at this point, data is invalid and fec is good -> replace data with fec
        erased_blocks[nr_fec_blocks] = di;
        fec_block_nos[nr_fec_blocks] = fi;
        myfec->fec_blocks[nr_fec_blocks] = myfec->fec_pkgs[fi].data;
        di++;
        fi++;
        nr_fec_blocks++;
      }

      int reconstruction_failed = datas_missing_c + datas_corrupt_c > good_fecs_c;

      if(reconstruction_failed) {
        //we did not have enough FEC packets to repair this block
        rx_status->damaged_block_cnt++;
        printf("Could not fully reconstruct block %x! Damage rate: %f (%d / %d blocks)\n", \
  	  last_block_num, 1.0 * rx_status->damaged_block_cnt / rx_status->received_block_cnt, rx_status->damaged_block_cnt, rx_status->received_block_cnt);
        printf("Data mis: %d\tData corr: %d\tFEC mis: %d\tFEC corr: %d\n", datas_missing_c, datas_corrupt_c, fecs_missing_c, fecs_corrupt_c);
      }

      //decode data and write it to STDOUT
//      fec_decode((unsigned int) param_packet_length, data_blocks, param_data_packets_per_block, fec_blocks, fec_block_nos, erased_blocks, nr_fec_blocks);
//      fec_decode(myfec->fec_p, myfec->inpkts, myfec->outpkts, myfec->indexes, myfec->sz);

      for(i=0; i<param_data_packets_per_block; ++i) {
        payload_header_t *ph = (payload_header_t*)myfec->data_blocks[i];

        if(!reconstruction_failed || myfec->data_pkgs[i].valid) {
        //if reconstruction did fail, the data_length value is undefined. better limit it to some sensible value
          if(ph->data_length > param_packet_length)
            ph->data_length = param_packet_length;

          write(STDOUT_FILENO, (char *)(myfec->data_blocks[i]) + sizeof(payload_header_t), ph->data_length);
          fflush(stdout);
        }
      }

      //reset buffers
      for(i=0; i<param_data_packets_per_block + param_fec_packets_per_block; ++i) {
        packet_buffer_t *p = packet_buffer_list + i;
        p->valid = 0;
        p->crc_correct = 0;
        p->len = 0;
      }
    }

    block_buffer_list[min_block_num_idx].block_num = block_num;
    max_block_num = block_num;
  }

  //find the buffer into which we have to write this packet
  block_buffer_t *rbb = block_buffer_list;
  for(i=0; i<param_block_buffers; ++i) {
    if(rbb->block_num == block_num) {
      break;
    }
    rbb++;
  }

  //check if we have actually found the corresponding block. this could not be the case due to a corrupt packet
  if(i != param_block_buffers) {
    packet_buffer_t *packet_buffer_list = rbb->packet_buffer_list;
    packet_num = wph->sequence_number % (param_data_packets_per_block+param_fec_packets_per_block); 
    //if retr_block_size would be limited to powers of two, this could be replace by a locical and operation

    //only overwrite packets where the checksum is not yet correct. otherwise the packets are already received correctly
    if(packet_buffer_list[packet_num].crc_correct == 0) {
      memcpy(packet_buffer_list[packet_num].data, data, data_len);
      packet_buffer_list[packet_num].len = data_len;
      packet_buffer_list[packet_num].valid = 1;
      packet_buffer_list[packet_num].crc_correct = crc_correct;
    }
  }
}

/*****************************************************************************/
void process_packet(myfec_t *myfec,int *seq,monitor_interface_t *interface,wifi_adapter_rx_status_t *rx_status, block_buffer_t *block_buffer_list) {

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

  process_payload(myfec,seq,puint8Payload, bytes, checksum_correct,block_buffer_list,rx_status);
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  myfec_t myfec;
  monitor_interface_t interface;
  wifi_adapter_rx_status_t rx_status;
  memset(&rx_status,0,sizeof(rx_status));

  init(argv[1], &interface,&myfec);

  int num_packets = param_data_packets_per_block+param_fec_packets_per_block;
  block_buffer_t *block_buffer_list = malloc(sizeof(block_buffer_t)* param_block_buffers);
  for(int i=0; i<param_block_buffers; ++i) {
    block_buffer_list[i].block_num = -1;
    block_buffer_list[i].packet_buffer_list = malloc((sizeof(packet_buffer_t) * num_packets));
    for (int j=0;j<= num_packets;j++) {
      memset(&block_buffer_list[i].packet_buffer_list[j],0,sizeof(packet_buffer_t));
      block_buffer_list[i].packet_buffer_list[j].data = malloc(MAX_PACKET_LENGTH);
    }
  }

  int seq=0;
  for(;;) {
    fd_set readset;
    FD_ZERO(&readset);

    FD_SET(interface.selectable_fd, &readset);

    int n = select(interface.selectable_fd+1, &readset, NULL, NULL, NULL);

    if(n == 0) break;
    if(FD_ISSET(interface.selectable_fd, &readset)) {
      process_packet(&myfec,&seq,&interface, &rx_status, block_buffer_list);
    }
  }
}


