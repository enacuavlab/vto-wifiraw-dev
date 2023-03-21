#include "wfb.h"

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char szErrbuf[PCAP_ERRBUF_SIZE];szErrbuf[0] = '\0';
  pcap_t *ppcap = pcap_open_live(argv[1], 100, 0, 20, szErrbuf);
  if (ppcap == NULL) exit(-1);
  if(pcap_setnonblock(ppcap, 0, szErrbuf) < 0) exit(-1);

  uint8_taRadiotapHeader[8]=0x48; /* (0x48 x 500 kbps) = data rate : 36Mb/s  */
  uint8_taIeeeHeader_data[5] = 0; /* standard DATA on port 0 (0-255) */
  int headerSize1 = sizeof(uint8_taRadiotapHeader) + sizeof (uint8_taIeeeHeader_data);
  int headerSize2 = headerSize1 + sizeof(wifi_packet_header_t);
  int headerSize3 = headerSize2 + sizeof(payload_header_t);

  pkt_t pkts_data[fec_n];
  for (int i=0;i<fec_n;i++) {  
    pkts_data[i].data=malloc(PKT_SIZE);               // data with headers
    pkts_data[i].len= 0;                              // len wihout headers, from 0 to PKT_DATA
    memcpy(pkts_data[i].data, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
    memcpy(pkts_data[i].data + sizeof(uint8_taRadiotapHeader), uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));
  }
  pkt_t pkts_fec[fec_k];
  for (int i=0;i<fec_k;i++) { 
    pkts_fec[i].data=malloc(PKT_SIZE);              
    pkts_fec[i].len= 0;
    memcpy(pkts_fec[i].data, uint8_taRadiotapHeader, sizeof(uint8_taRadiotapHeader));
    memcpy(pkts_fec[i].data + sizeof(uint8_taRadiotapHeader), uint8_taIeeeHeader_data, sizeof (uint8_taIeeeHeader_data));
  }

  uint8_t *enc_in[fec_n];

  uint8_t *enc_out[fec_k];
  uint8_t enc_outdata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) enc_out[i] = enc_outdata[i];

//  uint8_t blocks_data[fec_n][PKT_DATA];
//  const unsigned char *blocks[fec_n];
//  for (int i=0;i<fec_n;i++) blocks[i] = &blocks_data[i];

//  uint8_t outblocks_data[fec_k][PKT_DATA];
//  unsigned char *outblocks[fec_k];
//  for (int i=0;i<fec_k;i++) outblocks[i] = &outblocks_data[i];

  unsigned block_nums[fec_n-fec_k];
  for (int i=0;i<(fec_n-fec_k);i++) block_nums[i] = i+fec_k;

  fec_t* fec_p = fec_new(fec_k,fec_n);

  fd_set rfds;struct timeval timeout;bool usefec;pkt_t *pkt_p;int inl, ret, nb_pkts;int nb_curr=0, nb_seq=0;
  bool interl = true;int di = 0,fi = 0, li=0;  
  for(;;) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeout.tv_sec = 1;
    ret = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout); 
    if (ret > 0) {
      pkt_p = &pkts_data[nb_curr];
      if (pkt_p->len == 0) enc_in[nb_curr] = pkt_p->data + headerSize3;    // get data block address (no memory copy)
      inl=read(STDIN_FILENO, pkt_p->data + headerSize3 + pkt_p->len, PKT_DATA - pkt_p->len);   // fill pkts with input$
      if (inl < 0) continue;
      pkt_p->len += inl;
      if (pkt_p->len == PKT_DATA) nb_curr++;                         // current packet is full, switch to next packet
      if (nb_curr == fec_n) ret = 0;          // all pkts are full, continue with send sequence below
    }
    if (ret == 0) { 
      if ((pkts_data[0].len) > 0) {                                 // timeout with data available to send, or full pkts to send
	if (nb_curr == fec_n) nb_pkts = fec_n;
	else nb_pkts = nb_curr+1;
	usefec = false;                                              // use fec when all full packet are sent
        if ((fec_k) && (nb_curr == fec_n)) usefec=true; 
        if (usefec) {
          fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, (fec_n - fec_k), PKT_DATA);
          for(int i=0; i<fec_k; ++i) {
            pkts_fec[i].len = (-PKT_DATA);                          // set unsigned data_length signed bit for fec
	    memcpy(pkts_fec[i].data + headerSize3, enc_outdata[i], PKT_DATA);
	  }
        }
	di=0;fi=0;li=0;
        while ((usefec && ((di < fec_n) || (fi < fec_k)))
          || (!usefec && (li < nb_pkts))) {                         // send data and fec interleaved, when needed
	  if (usefec) {	
            if (di < fec_n) {
              if (((fi < fec_k) && (interl)) || (fi == fec_k)) {
                  pkt_p = &pkts_data[di]; di ++;
                }
              }
  	    if ((fec_k) && (fi < fec_k)) {
                if (((di < fec_n) && (!interl)) || (di == fec_n)) {
                  pkt_p = &pkts_fec[fi]; fi ++;
                }
            }
	  } else {
              pkt_p = &pkts_data[li]; li ++;
	  }
          interl = !interl; // toggle
          ((wifi_packet_header_t *)(pkt_p->data + headerSize1))->sequence_number = nb_seq;
	  ((payload_header_t *)(pkt_p->data + headerSize2))->data_length = pkt_p->len;
	  ret = pcap_inject(ppcap, pkt_p->data, PKT_SIZE);

	  pkt_p->len = 0; 
	  nb_seq++;
	}
	nb_curr = 0;
      }
    }
  }
}
