#include <string.h>
#include <stdio.h>

#include "fec.h"


/*****************************************************************************/
void _hexwrite(unsigned char*s, size_t l) {
  size_t i;
  for (i = 0; i < l; i++)
    printf("%.2x", s[i]);
}

/*****************************************************************************/
int main(int argc, char *argv[]) {

  unsigned char b0c[8], b1c[8];
  unsigned char b0[8], b1[8], b2[8], b3[8], b4[8], b5[8], b6[8], b7[8];
  unsigned char e0[8], e1[8], e2[8], e3[8];

  const unsigned char *blocks[8] = {b0, b1, b2, b3, b4, b5, b6, b7};
  unsigned char *outblocks[4] = {e0, e1, e2, e3};
  unsigned block_nums[4] = {4, 5, 6, 7}; // fecnum >= code->k)

  fec_t *const fec = fec_new(4, 8);
  fec_encode(fec, blocks, outblocks, block_nums, 4, 8);

//  const unsigned char *inpkts[] = {b3, b4, b2};
  const unsigned char *inpkts[] = {b3, b4, b2, b1};
  unsigned char *outpkts[] = {b0, b1, b2, b3};

  // option A nothing to decode, outpkts unchanged
  unsigned indexesA[] = {0, 1, 2, 3}; // (index[row] == row)
  fec_decode(fec, inpkts, outpkts, indexesA, 8);

  // option B 1 change 
  unsigned indexesB[] = {0, 1, 2, 4}; // (index[row] >= code->k) 
  fec_decode(fec, inpkts, outpkts, indexesB, 8);

  // option C 2 changes 
  unsigned indexesC[] = {0, 1, 4, 5}; // (index[row] >= code->k) 
  fec_decode(fec, inpkts, outpkts, indexesC, 8);

  // option D 3 changes 
  unsigned indexesD[] = {0, 4, 5, 6}; // (index[row] >= code->k) 
  fec_decode(fec, inpkts, outpkts, indexesD, 8);

  // option E 4 changes 
  unsigned indexesE[] = {4, 5, 6, 7}; // (index[row] >= code->k) 
  fec_decode(fec, inpkts, outpkts, indexesE, 8);


/*
  memset(b0, 1, 8);
  memset(b1, 2, 8);
  memset(b2, 3, 8);

  printf("before encoding:\n");
  printf("b0: "); _hexwrite(b0, 8); printf(", ");
  printf("b1: "); _hexwrite(b1, 8); printf(", ");
  printf("b2: "); _hexwrite(b2, 8); printf(", ");
  printf("\n");
*/
/*
  printf("\nafter encoding:\n");
  printf("b3: "); _hexwrite(b3, 8); printf(", ");
  printf("b4: "); _hexwrite(b4, 8); printf(", ");
  printf("\n");

  memcpy(b0c, b0, 8); memcpy(b1c, b1, 8);
*/
/*
  printf("\n\nafter decoding:\n");
  printf("b0: "); _hexwrite(b0, 8); printf(", ");
  printf("b1: "); _hexwrite(b1, 8);
  printf("b2: "); _hexwrite(b2, 8);
  printf("\n");

  if ((memcmp(b0, b0c,8) == 0) && (memcmp(b1, b1c,8) == 0))
    printf("\nTRUE\n");
  else
    printf("\nFALSE\n");
*/
}
