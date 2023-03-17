#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "fec.h"



/*****************************************************************************/
int fec_k = 4;
int fec_n = 8;

#define PKT_DATA 1466

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t *enc_in[fec_n];
  uint8_t enc_indata[fec_n][PKT_DATA];
  for (int i=0;i<fec_n;i++) enc_in[i] = enc_indata[i];

  uint8_t *enc_out[fec_k];
  uint8_t enc_outdata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) enc_out[i] = enc_outdata[i];

  unsigned block_nums[] = { 0 + fec_k, 1 + fec_k, 2 + fec_k, 3 + fec_k };

  for (int i=0;i<fec_n;i++) {for (int j=0;j<PKT_DATA;j++) {enc_indata[i][j] = rand()%100;}}

  fec_t *fec_p = fec_new(fec_k, fec_n);
  fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, (fec_n - fec_k), PKT_DATA);
  free(fec_p);

  printf("send data and fec frames\n");

  uint8_t *dec_in[fec_k];
  uint8_t dec_indata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) dec_in[i] = dec_indata[i];

  uint8_t *dec_out[fec_n - fec_k];
  uint8_t dec_outdata[fec_n - fec_k][PKT_DATA];
  for (int i=0;i<(fec_n - fec_k);i++) dec_out[i] = dec_outdata[i];

  printf("receive data and fec frames\n");

  for (int i=0;i<fec_n;i++) memcpy(dec_indata[i],enc_indata[i],PKT_DATA);
  for (int i=0;i<fec_k;i++) memcpy(dec_outdata[i],enc_outdata[i],PKT_DATA);

  bool map[fec_n];
  memset(map,1,sizeof(map)); // all true, no difference => index : {0, 1, 2, 3}
			     
  printf("data frame is alterated\n");
  printf("%x \n",dec_indata[1][5]);
  dec_indata[1][5]++ ;               // element 5 from dataframe 1 in incremeted
  printf("%x \n",dec_indata[1][5]);
  map[3] = 0;                        // frame alteration (ex wrong crc) is notified

  uint8_t *data_frame[fec_n];
  uint8_t data_frame_data[fec_n][PKT_DATA];
  for (int i=0;i<fec_n;i++) data_frame[i] = data_frame_data[i];

  uint8_t *fec_frame[fec_k];
  uint8_t fec_frame_data[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) fec_frame[i] = fec_frame_data[i];

			     
  unsigned index[fec_k];
  int j = fec_k;
  int ob_idx = 0;

  for(int i=0; i < fec_k; i++) {
    if(map[i]) {
      dec_in[i] = fec_frame[i];
      index[i] = i;
    } else {
      for(;j < fec_n; j++) {
        if(map[j]) {
          dec_in[i] = data_frame[j];
          dec_out[ob_idx++] = data_frame[i];
          index[i] = j;
          j++;
          break;
	} 
      }
    }
  }

  // index = {0, 1, 2, 4}
  
  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index, PKT_DATA);
  free(fec_p);
 
  printf("%x \n",dec_out[1][5]);
}
