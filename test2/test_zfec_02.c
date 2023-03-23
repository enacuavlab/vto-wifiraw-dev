#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "fec.h"

#define PKT_DATA 1466
#define fec_k 4
#define fec_n 8
// fec_n = original data + extra data (fec_k)

uint8_t *enc_in[fec_k];        

/*****************************************************************************/
void apply_fec(bool *map_data, bool *map_fec, uint8_t *data_frame[], uint8_t *fec_frame[]) {

  uint8_t fec_d = (fec_n - fec_k);

  bool fec_used[fec_d];

  unsigned indexes[fec_k];
  uint8_t *dec_in[fec_k];

  uint8_t *dec_out[fec_d];
  uint8_t dec_outdata[fec_d][PKT_DATA];
  for (int i=0;i<fec_d;i++) {dec_out[i] = dec_outdata[i];}

  // 1) set decoder options with dec_in and indexes
  // 2) start building final frame with dec_out (decode will produce in dec_out, only packet not present in dec_in)
  memset(fec_used,0,sizeof(fec_used));
  for(int i=0; i < fec_k; i++)   {
    if(map_data[i]) {
      for (int j=0; j < fec_d; j++) {
        if ((!map_fec[j])&&(!fec_used[j])) {
          dec_in[i] = fec_frame[j];
          indexes[i] = j+fec_k;
	  fec_used[j]=1;
	  break;
	}
      }
    } else {
      dec_in[i] = data_frame[i];
      dec_out[i] = data_frame[i];
      indexes[i] = i;
    }
  }

  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",indexes[i]); printf(" ]\n");

  fec_t *fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);
  free(fec_p);

  printf("valid and decode outputs [");for (int i=0;i < fec_d; i++) printf(" %d ",*dec_out[i]); printf(" ]\n");
  if (!memcmp(enc_in,dec_out,sizeof(uint8_t))) {
    printf("!!!! \ncheck KO \n!!!!\n");
  }
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t fec_d = (fec_n - fec_k);

  uint8_t enc_indata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) enc_in[i] = enc_indata[i];

  uint8_t *enc_out[fec_d];
  uint8_t enc_outdata[fec_d][PKT_DATA];
  for (int i=0;i<fec_d;i++) enc_out[i] = enc_outdata[i];

  unsigned block_nums[fec_d]; // desired check blocks (id >= k), block_nums[i] >= code->k
  for (int i=0;i<fec_d;i++) block_nums[i] = i + fec_k;

  for (int i=0;i<fec_k;i++) {for (int j=0;j<PKT_DATA;j++) {enc_indata[i][j] = rand()%100;}}

  printf("original data [");for (int i=0;i < fec_k; i++) printf(" %d ",*enc_in[i]); printf(" ]\n");
  printf("encode inputs num [");for (int i=0;i < fec_d; i++) printf(" %d ",block_nums[i]); printf(" ]\n");

  fec_t *fec_p = fec_new(fec_k, fec_n);
  fec_encode(fec_p, (const uint8_t**)enc_in, enc_out, block_nums, fec_d, PKT_DATA);
  free(fec_p);

  printf("encoded fec from data [");for (int i=0;i < fec_d; i++) printf(" %d ",*enc_out[i]); printf(" ]\n");

  printf("send and receive data and tagged fec frames\n");

  uint8_t *data_frame[fec_d];
  for (int i=0;i<fec_d;i++) data_frame[i] = enc_in[i];   // get data
  uint8_t *fec_frame[fec_k];
  for (int i=0;i<fec_k;i++) fec_frame[i] = enc_out[i];   // get encoded data

  printf("set recovery options\n");

  bool map_data[(fec_n-fec_k)];
  memset(map_data,0,sizeof(map_data)); // set with crc ok
  bool map_fec[fec_k];
  memset(map_fec,0,sizeof(map_fec));   // set with crc ok 

  // Recovery for 0 to fec_k, position in data frames
  // recovery using good (crc ok) fec frames  

  // make all combination of failures map_data and map_fec 
  for(uint8_t val_data=0;val_data<16;val_data++) {
    for(int j_data=3;j_data>=0;j_data--) {
      map_data[j_data] = (((uint8_t *)&val_data)[0] >> j_data) & 1;
    }    
    for(uint8_t val_fec=0;val_fec<16;val_fec++) {
      for(int j_fec=3;j_fec>=0;j_fec--) {
        map_fec[j_fec] = (((uint8_t *)&val_fec)[0] >> j_fec) & 1;
      }
      printf("------------------------------------------------------------------\n");
      printf("[%d %d %d %d] [%d %d %d %d]\n",map_data[0],map_data[1],map_data[2],map_data[3],map_fec[0],map_fec[1],map_fec[2],map_fec[3]);
  
      uint8_t map_cpt=0,fec_cpt=0;
      for (int i=0;i<fec_k;i++) { 
        if (map_data[i]) map_cpt++;
        if (map_fec[i]) fec_cpt++;
      }
      
      if (map_cpt == 0) {
        printf("no data failures\n");
        continue;
      }
      
      if (map_cpt > (fec_k - fec_cpt)) {
        printf("(%d) data failures, cannot be recovered with (%d) valid extra data redundancy\n",map_cpt,(fec_k-fec_cpt));
        continue;
      }
      
      apply_fec(map_data,map_fec,data_frame,fec_frame);
    }
  }
}
