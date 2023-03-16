#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "fec.h"



/*****************************************************************************/
int param_fec_packets_per_block = 4;
int param_data_packets_per_block = 8;

#define PKT_DATA 1466

/*****************************************************************************/
void _hexwrite(unsigned char*s, size_t l) {
  size_t i;
  for (i = 0; i < l; i++)
    printf("%.2x", s[i]);
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  uint8_t rand_data[param_data_packets_per_block][PKT_DATA];
  for (int i=0;i<param_data_packets_per_block;i++) {
    for (int j=0;j<PKT_DATA;j++) rand_data[i][j]=rand()%100;
  }
  uint8_t rand_fec[param_fec_packets_per_block][PKT_DATA];
  for (int i=0;i<param_fec_packets_per_block;i++) {
    for (int j=0;j<PKT_DATA;j++) rand_fec[i][j]=rand()%100;
  }
  uint8_t rand_data_fec[(param_data_packets_per_block - param_fec_packets_per_block)][PKT_DATA];
  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) {
    for (int j=0;j<PKT_DATA;j++) rand_data_fec[i][j]=rand()%100;
  }




  uint8_t blocks_data[param_data_packets_per_block][PKT_DATA];
  const unsigned char *blocks[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) blocks[i] = &blocks_data[i];

  uint8_t outblocks_data[param_fec_packets_per_block][PKT_DATA];
  unsigned char *outblocks[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) outblocks[i] = &outblocks_data[i];

  unsigned block_nums[] = {4, 5, 6, 7};
//  unsigned block_nums[param_data_packets_per_block - param_fec_packets_per_block];
//  for (int i=0;i<num_block_nums;i++) block_nums[i]=param_fec_packets_per_block;



  for (int i=0;i<param_data_packets_per_block;i++) memcpy(blocks_data[i], rand_data[i], PKT_DATA);
  for (int i=0;i<param_fec_packets_per_block;i++) memcpy(outblocks_data[i], rand_fec[i], PKT_DATA);

  fec_t  *fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);
  fec_encode(fec_p, blocks, outblocks,  block_nums, (param_data_packets_per_block - param_fec_packets_per_block), PKT_DATA);

//  blocks_data[3][4] = 1 + blocks_data[3][4]; // insert difference

  for (int i=0;i<param_data_packets_per_block;i++) {
    if( 0 != memcmp(blocks_data[i], rand_data[i], PKT_DATA)) {
      printf("blocks_data have changed\n");
      break;
    }
  }

  for (int i=0;i<param_fec_packets_per_block;i++) {
    if( 0 != memcmp(outblocks_data[i], rand_fec[i], PKT_DATA)) {
      printf("outblocks_data  have changed\n");
      break;
    }
  }

  free(fec_p);

  uint8_t inpkts_data[param_fec_packets_per_block][PKT_DATA];
  const unsigned char *inpkts[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) inpkts[i] = &inpkts_data[i];

  uint8_t outpkts_data[param_data_packets_per_block - param_fec_packets_per_block][PKT_DATA];
  unsigned char *outpkts[param_data_packets_per_block - param_fec_packets_per_block];
  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) outpkts[i] = &outpkts_data[i];

  unsigned indexes[param_fec_packets_per_block];


  for (int i=0;i<param_fec_packets_per_block;i++) memcpy(inpkts_data[i], rand_fec[i], PKT_DATA);
  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) memcpy(outpkts_data[i], rand_data_fec[i], PKT_DATA);

  fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);
//  fec_decode(fec_p, inpkts, outpkts, indexes, PKT_DATA);
}
