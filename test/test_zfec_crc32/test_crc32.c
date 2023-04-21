#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// (radiotap + 802.11) : wireshark capture copy as escapted strings ...
uint8_t pkt[] = {
  0x00,0x00,0x20,0x00,0xae,0x40,0x00,0xa0,0x20,0x08,0x00,0xa0,0x20,0x08,0x00,0x00,
  0x10,0x0c,0x3c,0x14,0x40,0x01,0xd7,0x00,0x5d,0x00,0x00,0x00,0xd6,0x00,0xd8,0x01,
  0x88,0x00,0x00,0x00,0xff,0x05,0xff,0xff,0xff,0xff,0x23,0x23,0x23,0x23,0x23,0x23,
  0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x20,0x00,0xaa,0xaa,0x03,0x00,0x00,0x00,
  0x88,0xb5,0xa9,0xe2,0x25,0x4a };


//uint8_t pkt[] = {'1','2','3','4','5','6','7','8','9'}; // sample with knowm crc32 = cbf43926

uint32_t crc32_table[256];

void build_crc32_table(void) {
  for(uint32_t i=0;i<256;i++) {
    uint32_t ch=i;
    uint32_t crc=0;
    for(uint32_t j=0;j<8;j++) {
      uint32_t b=(ch^crc)&1;
      crc>>=1;
      if(b) crc=crc^0xEDB88320;
      ch>>=1;
    }
    crc32_table[i]=crc;
  }
}


uint32_t crc32_fast(const uint8_t *s,uint32_t n) {
  uint32_t crc=0xFFFFFFFF;
  for(uint32_t i=0;i<n;i++) {
    uint8_t ch=s[i];
    uint32_t t=(ch^crc)&0xFF;
    crc=(crc>>8)^crc32_table[t];
  }
  return ~crc;
}


uint32_t crc32(const uint8_t *s,uint32_t n) {
  uint32_t crc=0xFFFFFFFF;
  for(uint32_t i=0;i<n;i++) {
    uint8_t ch=s[i];
    for(uint32_t j=0;j<8;j++) {
      uint32_t b=(ch^crc)&1;
      crc>>=1;
      if(b) crc=crc^0xEDB88320;
      ch>>=1;
    }
  }
  return ~crc;
}


int main(int argc, char *argv[]) {

  uint32_t bytes=(sizeof(pkt));
  printf("(%d)\n",bytes);

  uint32_t crc;
  uint16_t u16HeaderLen = (pkt[2] + (pkt[3] << 8));
  uint32_t dataLen = bytes - u16HeaderLen - sizeof(crc);
  uint32_t a = crc32(&pkt[u16HeaderLen],dataLen);

  build_crc32_table();
  uint32_t b = crc32_fast(&pkt[u16HeaderLen],dataLen);

  memcpy(&crc,&pkt[bytes-sizeof(crc)],sizeof(crc));

  printf("(%x)(%x)(%x)\n",a,b,crc);
  if (crc == b) printf("Check OK\n");else printf("NO Check\n");
}
