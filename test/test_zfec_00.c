#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "fec.h"

/*
https://blog.est.im/post/50975299198
*/
/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t PKT_DATA = 1, fec_k = 2, fec_n = 3; // fec_n = original data + extra data (fec_k)

  uint8_t *enc_in[fec_k];        
  uint8_t enc_indata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) enc_in[i] = enc_indata[i];

  uint8_t *enc_out[fec_n-fec_k];
  uint8_t enc_outdata[fec_n][PKT_DATA];
  for (int i=0;i<(fec_n-fec_k);i++) enc_out[i] = enc_outdata[i];

  unsigned block_nums[(fec_n-fec_k)]; // desired check blocks (id >= k), block_nums[i] >= code->k
  for (int i=0;i<(fec_n-fec_k);i++) block_nums[i] = i + fec_k;

  for (int i=0;i<fec_k;i++) {for (int j=0;j<PKT_DATA;j++) {enc_indata[i][j] = rand()%100;}}

  printf("original data [");for (int i=0;i < fec_k; i++) printf(" %d ",*enc_in[i]); printf(" ]\n");
  printf("encode inputs num [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",block_nums[i]); printf(" ]\n");

  fec_t *fec_p = fec_new(fec_k, fec_n);
  fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, (fec_n - fec_k), PKT_DATA);
  free(fec_p);

  printf("encoded fec from data [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*enc_out[i]); printf(" ]\n");

  printf("send and receive data and tagged fec frames\n");

  uint8_t *data_frame[(fec_n-fec_k)];
  for (int i=0;i<(fec_n-fec_k);i++) data_frame[i] = enc_in[i];   // get data
  uint8_t *fec_frame[fec_k];
  for (int i=0;i<fec_k;i++) fec_frame[i] = enc_out[i];          // get encoded data

  printf("set recovery options\n");
         
  uint8_t *dec_in[fec_k]; 
  dec_in[0] = data_frame[0];  // primary (if i present must be at index i)
  dec_in[1] = fec_frame[0];   // secondary block  (anywhere)

  unsigned indexes[] = {0,2};  // (index[row] >= code->k) || (index[row] == row)

  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",indexes[i]); printf(" ]\n");

  uint8_t *dec_out[(fec_n-fec_k)]; // only packet not present in input, will be reconstruct and writtent
  uint8_t dec_outdata[(fec_n-fec_k)][PKT_DATA];
  for (int i=0;i<(fec_n-fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  uint8_t *frame_out[fec_k]; 
  frame_out[0] = data_frame[0];
  frame_out[1] = dec_out[0];

  printf("rebuild data [");for (int i=0;i < fec_k; i++) printf(" %d ",*frame_out[i]); printf(" ]\n");
}
