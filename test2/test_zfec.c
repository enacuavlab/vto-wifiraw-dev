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



 // blocks : the "primary blocks" i.e. the chunks of the input data

  uint8_t blocks_data[param_data_packets_per_block][PKT_DATA];
  const unsigned char *blocks[param_data_packets_per_block];
  for (int i=0;i<param_data_packets_per_block;i++) blocks[i] = &blocks_data[i];

  // outblocks : fecs buffers into which the secondary blocks will be written

  uint8_t outblocks_data[param_fec_packets_per_block][PKT_DATA];
  unsigned char *outblocks[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) outblocks[i] = &outblocks_data[i];

  // block_nums : the numbers of the desired check blocks (the id >= k) which fec_encode() 
  // will produce and store into the buffers of the fecs parameter
  
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

  //  inpkts : array of packets (size k); 
  //  If a primary block, i, is present then it must be at index i. 
  //  Secondary blocks can appear anywhere

  uint8_t inpkts_data[param_fec_packets_per_block][PKT_DATA];
  const unsigned char *inpkts[param_fec_packets_per_block];
  for (int i=0;i<param_fec_packets_per_block;i++) inpkts[i] = &inpkts_data[i];

  // outpkts : array of buffers into which the reconstructed output packets will be written 
  // (only packets which are not present in the inpkts input will be reconstructed and written to outpkts)

  uint8_t outpkts_data[param_data_packets_per_block - param_fec_packets_per_block][PKT_DATA];
  unsigned char *outpkts[param_data_packets_per_block - param_fec_packets_per_block];
  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) outpkts[i] = &outpkts_data[i];

  // indexes : array of the blocknums of the packets in inpkts
 
  //unsigned indexes[param_fec_packets_per_block];
  unsigned indexes[] = {0, 1, 2, 3}; // No changes
  //unsigned indexes[] = {4, 1, 2, 3}; // outpkts_data changed [0]
  //unsigned indexes[] = {0, 4, 2, 3}; // outpkts_data changed [0]
  //unsigned indexes[] = {4, 5, 2, 3}; // outpkts_data changed [0][1]
  //unsigned indexes[] = {4, 5, 6, 7}; // outpkts_data changed [0][1][2][4]


  for (int i=0;i<param_fec_packets_per_block;i++) memcpy(inpkts_data[i], rand_fec[i], PKT_DATA);
  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) memcpy(outpkts_data[i], rand_data_fec[i], PKT_DATA);

  inpkts_data[3][4] = 1 + inpkts_data[3][4]; // insert difference in pkt 3

  fec_p = fec_new(param_fec_packets_per_block,param_data_packets_per_block);
  fec_decode(fec_p, inpkts, outpkts, indexes, PKT_DATA);

  for (int i=0;i<(param_data_packets_per_block - param_fec_packets_per_block);i++) {
    if( 0 != memcmp(outpkts_data[i], rand_data_fec[i], PKT_DATA)) {
      printf("outpkts_data have changed [%d]\n",i);
    }
  }

  for (int i=0;i<param_fec_packets_per_block;i++) {
    if( 0 != memcmp(inpkts_data[i], rand_fec[i], PKT_DATA)) {
      printf("inpkts_data  have changed\n");
      break;
    }
  }
}
