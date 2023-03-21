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

  printf("original data [");for (int i=0;i < fec_n; i++) printf(" %d ",*enc_in[i]); printf(" ]\n");
  printf("encode inputs num [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",block_nums[i]); printf(" ]\n");

  fec_t *fec_p = fec_new(fec_k, fec_n);
  fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, (fec_n - fec_k), PKT_DATA);
  free(fec_p);

  printf("encoded fec from data [");for (int i=0;i < fec_k; i++) printf(" %d ",*enc_out[i]); printf(" ]\n");

  printf("send and receive data and tagged fec frames\n");

  uint8_t *data_frame[fec_n];
  for (int i=0;i<fec_n;i++) data_frame[i] = enc_in[i];
  uint8_t *fec_frame[fec_k];
  for (int i=0;i<fec_k;i++) fec_frame[i] = enc_out[i];

  printf("data frame is alterated\n");

  unsigned indexes[fec_k];

  bool map[fec_n];
  memset(map,0,sizeof(map));

  // Recovery for first 0 to fec_k, position in data frames
  // Data frames from fec_k to fec_n, cannot be recover (due to choosen fec encode index)

  // Uncomment one of these lines to make the test

// single failure
// map // not set
//  map[0] = 1; 
//  map[1] = 1;
//  map[2] = 1; 
//  map[3] = 1;

  // multiple failure
//  map[0] = 1; map[1] = 1;
//  map[1] = 1; map[2] = 1;
//  map[2] = 1; map[3] = 1;
//  map[0] = 1; map[2] = 1;
//  map[0] = 1; map[3] = 1;
//  map[1] = 1; map[3] = 1;
//  map[0] = 1; map[1] = 1; map[2] = 1;
//  map[1] = 1; map[2] = 1; map[3] = 1;
//  map[0] = 1; map[1] = 1; map[3] = 1;

  uint8_t *dec_in[fec_k];
  uint8_t *dec_out[fec_n - fec_k];
  uint8_t dec_outdata[fec_n - fec_k][PKT_DATA];

  for(int i=0; i < fec_k; i++)   {
    if(map[i]) {
      dec_in[i] = fec_frame[i];
      indexes[i] = i+fec_k;
    } else {
      dec_in[i] = data_frame[i];
      indexes[i] = i;
    }
  }

  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",indexes[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  uint8_t *data_frame_out[fec_n];
  for (int i=fec_k;i<fec_n;i++) data_frame_out[i] = data_frame[i]; 

  uint8_t error_pos = 0;
  for (int i=0;i<fec_k;i++) {
    if (map[i]) {
      data_frame_out[i] = dec_out[error_pos]; 
      error_pos++;
    } else { data_frame_out[i] = dec_in[i];}
  }

  printf("rebuild outputs [");for (int i=0;i < fec_n; i++) printf(" %d ",*data_frame_out[i]); printf(" ]\n");
}
