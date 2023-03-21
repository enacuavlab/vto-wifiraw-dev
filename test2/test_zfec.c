#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "fec.h"


/**
 * @param inpkts the "primary blocks" i.e. the chunks of the input data
 * @param fecs buffers into which the secondary blocks will be written
 * @param block_nums the numbers of the desired check blocks (the id >= k) which fec_encode() will produce and store into the buffers of the fecs parameter
 * @param num_block_nums the length of the block_nums array
 * @param sz size of a packet in bytes
 */
//void fec_encode(const fec_t* code, const gf*restrict const*restrict const src, gf*restrict const*restrict const fecs, const unsigned*restrict const block_nums, size_t num_block_nums, size_t sz);

/**
 * @param inpkts an array of packets (size k); If a primary block, i, is present then it must be at index i. Secondary blocks can appear anywhere.
 * @param outpkts an array of buffers into which the reconstructed output packets will be written (only packets which are not present in the inpkts input will be reconstructed and written to outpkts)
 * @param index an array of the blocknums of the packets in inpkts
 * @param sz size of a packet in bytes
 */
//void fec_decode(const fec_t* code, const gf*restrict const*restrict const inpkts, gf*restrict const*restrict const outpkts, const unsigned*restrict const index, size_t sz);


/*****************************************************************************/
int fec_k = 4;
int fec_n = 8;

#define PKT_DATA 2
//#define PKT_DATA 1466

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t *enc_in[fec_n];
  uint8_t enc_indata[fec_n][PKT_DATA];
  for (int i=0;i<fec_n;i++) enc_in[i] = enc_indata[i];

  uint8_t *enc_out[fec_k];
  uint8_t enc_outdata[fec_k][PKT_DATA];
  for (int i=0;i<fec_k;i++) enc_out[i] = enc_outdata[i];

  unsigned block_nums[] = { 0 + fec_k, 1 + fec_k, 2 + fec_k, 3 + fec_k };

//  for (int i=0;i<fec_n;i++) {for (int j=0;j<PKT_DATA;j++) {enc_indata[i][j] = rand()%100;}}
  for (int i=0;i<fec_n;i++) sprintf((char *)&enc_indata[i],"%d",i);

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

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : all fecs no data =>  one data provided\n");

  uint8_t *dec_in[fec_k];
  uint8_t dec_indata[fec_k][PKT_DATA];

  unsigned index[] = {4, 5, 6, 7}; // same as encoded block_nums
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index[i]); printf(" ]\n");

  uint8_t *dec_out[fec_n - fec_k];
  uint8_t dec_outdata[fec_n - fec_k][PKT_DATA];
  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(&dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : one first data(index 0), remained fecs => three data remaining provided\n");

  unsigned index0[] = {0, 5, 6, 7};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[0] = data_frame[0];		                // set first data (index 0)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index0[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index0, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : second data (index 1), remained fecs => three data remaining provided\n");

  unsigned index1[] = {4, 1, 6, 7};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[1] = data_frame[1];                            // set second data (index 1)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index1[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index1, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : third data (index 2), remained fecs => three data remaining provided\n");

  unsigned index2[] = {4, 5, 2, 7};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[2] = data_frame[2];                            // set third data (indfex 2)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index2[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index2, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : fourth data (index 3), remained fecs => three data remaining  provided\n");

  unsigned index3[] = {4, 5, 6, 3};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[3] = data_frame[3];                            // set fourth data (index 3)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index3[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index3, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : combine first and second data (index 0,1), remained fecs => two data remaining provided\n");

  unsigned index4[] = {0, 1, 6, 7};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[0] = data_frame[0];                            // set first data (index 0)
  dec_in[1] = data_frame[1];                            // set second data (index 1)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index4[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index4, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("select recovery decode option : combine first,second and third data (index 0,1,2), remained fecs => one remaining data provided\n");

  unsigned index5[] = {0, 1, 2, 7};
  for (int i=0;i<fec_k;i++) dec_in[i] = fec_frame[i]; // all fecs
  dec_in[0] = data_frame[0];                            // set first data (index 0)
  dec_in[1] = data_frame[1];                            // set second data (index 1)
  dec_in[2] = data_frame[2];                            // set third data (index 2)
  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",index5[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index5, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");

  printf("---------------------------------------------------------------------\n");
  printf("---------------------------------------------------------------------\n");

  unsigned indexes[fec_k];
  int j = fec_k;
  int ob_idx = 0;

  bool map[fec_n];
  memset(map,1,sizeof(map)); // all true, no difference => index : {0, 1, 2, 3}
			   
  map[0] = 0;
			     
  for(int i=0; i < fec_k; i++)   {
    if(map[i]) {
      dec_in[i] = fec_frame[i];
      indexes[i] = i;
    } else {
      for(;j < fec_n; j++) {
        if(map[j]) {
          dec_in[i] = data_frame[j];       
          dec_out[ob_idx++] = fec_frame[i];
          index[i] = j;
          j++;
          break;
	} 
      }
    }
  }

  printf("decode inputs input [");for (int i=0;i < fec_k; i++) printf(" %d ",*dec_in[i]); printf(" ]\n");
  printf("decode inputs index [");for (int i=0;i < fec_k; i++) printf(" %d ",indexes[i]); printf(" ]\n");

  for (int i=0;i<(fec_n - fec_k);i++) {dec_out[i] = dec_outdata[i];memset(dec_out[i],0,PKT_DATA);}

  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, indexes, PKT_DATA);
  free(fec_p);

  printf("decode outputs [");for (int i=0;i < (fec_n-fec_k); i++) printf(" %d ",*dec_out[i]); printf(" ]\n");
}
 
/*
  bool map[fec_n];
  memset(map,1,sizeof(map)); // all true, no difference => index : {0, 1, 2, 3}
			     
  printf("data frame is alterated\n");
  printf("%x \n",dec_indata[1][5]);
  dec_indata[1][5]++ ;               // element 5 from dataframe 1 in incremeted
  printf("%x \n",dec_indata[1][5]);
  map[1] = 0;                        // frame alteration (ex wrong crc) is notified

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
          dec_out[ob_idx++] = fec_frame[i];
          index[i] = j;
          j++;
          break;
	} 
      }
    }
  }

  // index = {0, 4, 2, 3}
  
  fec_p = fec_new(fec_k, fec_n);
  fec_decode(fec_p, (const uint8_t**)dec_in, dec_out, index, PKT_DATA);
  free(fec_p);
 
  printf("%x \n",dec_out[1][5]);
}
*/
