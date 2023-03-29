#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>


uint8_t pkt[] = {
"\x00\x00\x20\x00\xae\x40\x00\xa0\x20\x08\x00\xa0\x20\x08\x00\x00" \
"\x10\x0c\x3c\x14\x40\x01\xef\x00\x1e\x00\x00\x00\xf2\x00\xea\x01" \
"\x88\x00\x00\x00\xff\x05\xff\xff\xff\xff\x23\x23\x23\x23\x23\x23" \
"\xff\xff\xff\xff\xff\xff\x40\x00\x20\x00\xaa\xaa\x03\x00\x00\x00" \
"\x88\xb5\x59\x55\x46\x7a"}; // captured with wireshark to check 4 last bytes crc32

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

  uint32_t a = crc32(pkt,bytes-4);

  build_crc32_table();
  uint32_t b = crc32_fast(pkt,bytes-4);

  printf("(%x)\n",pkt[bytes-5]);
  uint32_t c;
  memcpy(&c,&pkt[bytes-5],sizeof(c));

  printf("(%x)(%x)(%x)\n",a,b,c);
}
