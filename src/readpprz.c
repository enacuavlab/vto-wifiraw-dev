#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 1024

#define PPRZ_STX 0x99

#define PPRZ_MSG_ID_ROTORCRAFT_FP 147


/*****************************************************************************/
int main(int argc, char *argv[]) {

  int32_t east,north,up,veast;

  uint8_t buf[BUF_SIZE],*ptr;
  uint16_t len; 
  int16_t ret,fd;
  struct sockaddr_in addr;
  struct timeval timeout;
  fd_set readset_ref,readset;
  FD_ZERO(&readset_ref);

  if (-1 == (fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(4200);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
  if (-1 == bind(fd, (struct sockaddr *)&addr, sizeof(addr))) exit(-1);
  FD_SET(fd, &(readset_ref));

  for(;;) {
    FD_ZERO(&readset);
    readset = readset_ref;
    timeout.tv_sec = 1; timeout.tv_usec = 0;
    ret = select(fd + 1, &readset, NULL, NULL, &timeout);

    if (ret >0) {
      if(FD_ISSET(fd, &readset)) {
        len = read(fd, buf, BUF_SIZE);
        printf("\n[");	   
        for(int i=0;i<len;i++) printf(" %d ",buf[i]);
        printf("]\n");	   
/*
        if (buf[0] == PPRZ_STX) {
	  printf("(%d)\n",buf[5]);
          if (buf[5] == PPRZ_MSG_ID_ROTORCRAFT_FP) {

            ptr = &buf[6];
            memcpy(&east,ptr,sizeof(int32_t));ptr+=4;
            memcpy(&north,ptr,sizeof(int32_t));ptr+=4;
            memcpy(&up,ptr,sizeof(int32_t));ptr+=4;
            memcpy(&veast,ptr,sizeof(int32_t));
//	    printf("(%d)(%d(%d)(%d)\n",east,north,up,veast);

            printf("\n[");	   
            for(int i=0;i<len;i++) printf(" %d ",buf[i]);
            printf("]\n");	   
	  }
        }
*/
      }
    }
  }
}
