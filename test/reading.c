#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#define NAME_IN  "/tmp/socket1"
#define NAME_OUT "/tmp/socket2"

#define MAX_PACKET_SIZE 10
//#define MAX_PACKET_SIZE 1510
//#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(radiotap_header) - sizeof(ieee80211_header) - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(wpacket_hdr_t))

/*
time dd if=/dev/urandom of=/dev/shm/data.dump bs=1M count=1024


STREAM
socat "SYSTEM:dd if=/dev/shm/data.dump bs=1 count=1" UNIX:/tmp/socket1


option 1
--------
STREAM -> DATAGRAM
./reading

DATAGRAM
socat -x -d UNIX-RECV:/tmp/socket2 - | hexdump


option2
-------
socat UNIX-LISTEN:/tmp/socket2 - | hexdump -C

*/


int main(int argc, char **argv) {

  int msg_fd_in = 0;
  int fd_in = socket(AF_UNIX, SOCK_STREAM, 0); // enable partial reading
  struct sockaddr_un name_in;
  name_in.sun_family = AF_UNIX;
  strcpy(name_in.sun_path, NAME_IN);
  int ret = bind(fd_in, (struct sockaddr *) &name_in, sizeof(struct sockaddr_un));
  printf("bind ret=%d errno=%d\n",ret,errno);fflush(stdout);

  int fd_out = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct sockaddr_un name_out;
  name_out.sun_family = AF_UNIX;
  strcpy(name_out.sun_path, NAME_OUT);

  char buf[MAX_PACKET_SIZE];
  memset(buf,0x59,MAX_PACKET_SIZE);

  int data_read=0;
  int data_write=0;

  struct timespec begin;
  memset(&begin, 0, sizeof(begin));

  ret=listen(fd_in, 2);
  printf("listen=%d errno=%d\n",ret,errno);fflush(stdout);

  while(true) {

    printf("while\n");fflush(stdout);

    msg_fd_in=accept(fd_in,NULL,NULL);
    printf("accept=%d errno=%d\n",msg_fd_in,errno);fflush(stdout);

    data_read=1;
    while (data_read != 0) { // sender no more connected

      data_read = recv(msg_fd_in, buf, sizeof(buf), 0);  
      printf("data_read=%d errno=%d\n",data_read, errno);fflush(stdout);

      if (data_read != 0) {
        if (begin.tv_sec==0) clock_gettime(CLOCK_MONOTONIC, &begin);
      
        data_write = sendto(fd_out, buf, sizeof(buf), 0, &name_out, sizeof(struct sockaddr_un));
        printf("data_write=%d errno=%d\n",data_write, errno);fflush(stdout);
      
        printf("(");
        for (int i=0;i<data_read;i++) printf("%02x  ",buf[i] & 0xff);
        printf(")\n");
      
        memset(&buf,0x57,sizeof(buf));
      }
    }
    close(msg_fd_in);
  }

  close(fd_in);
  close(fd_out);
  unlink(NAME_IN);
}

/*
	  clock_gettime(CLOCK_MONOTONIC, &begin);
          double milliseconds = tm.tv_sec * 1000LL + tm.tv_nsec / 1000000;
          printf("(%f)",milliseconds);

          printf("(%d)(%d)",data_toread,data_read);fflush(stdout);
          for (int i=0;i<buf_size;i++) printf("%u ",buf[i]);
          printf("\n");
*/ 
