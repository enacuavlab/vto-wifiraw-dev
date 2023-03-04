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

#define MAX_SIZE_IN 4096
//#define MAX_SIZE_IN 8192

//#define MAX_PACKET_SIZE 1510
//#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(radiotap_header) - sizeof(ieee80211_header) - sizeof(wblock_hdr_t) - crypto_aead_chacha20poly1305_ABYTES - sizeof(wpacket_hdr_t))

/*
time dd if=/dev/urandom of=/dev/shm/data.dump bs=1M count=1024


STREAM
rm /tmp/socket1
socat "SYSTEM:dd if=/dev/shm/data.dump bs=1 count=1" UNIX-CONNECT:/tmp/socket1
(socat "SYSTEM:dd if=/dev/shm/data.dump bs=1 count=1" UNIX:/tmp/socket1)
(creates /tmp/socket1 or uses existing one)


option 1
--------
STREAM -> DATAGRAM
rm /tmp/socket1
./reading

DATAGRAM
socat -x -d UNIX-RECV:/tmp/socket2 - | hexdump
(start receiving at : 1 + MAX_PACKET_SIZE)
or
socat -x -d UNIX-RECVFROM:/tmp/socket2 - | hexdump
(receive first packet MAX_PACKET_SIZE)


option2
-------
STREAM
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

  char buf[MAX_SIZE_IN];
  memset(buf,0x59,MAX_SIZE_IN);

  int data_read=0;
  int data_write=0;
  int data_sum=0;
  double millsec;
  int sum_sent=0,sum_read=0;

  struct timespec begin,end;
  memset(&begin, 0, sizeof(begin));

  ret=listen(fd_in, 2);

  while(true) {
    msg_fd_in=accept(fd_in,NULL,NULL);
    data_read=1;
    while (data_read != 0) { // sender no more connected
      data_read = recv(msg_fd_in, buf, sizeof(buf), 0);  
      data_sum += data_read;
      sum_read ++;
      if (data_read != 0) {
        if ((begin.tv_sec+begin.tv_nsec) == 0) clock_gettime(CLOCK_MONOTONIC, &begin);
        data_write = sendto(fd_out, buf, sizeof(buf), 0, &name_out, sizeof(struct sockaddr_un));
	sum_sent ++;

//        printf("(");
//        for (int i=0;i<data_read;i++) printf("%02x  ",buf[i] & 0xff);
//        printf(")\n");
//
        memset(&buf,0x57,sizeof(buf));
      } else {
	if ((begin.tv_sec+begin.tv_nsec) != 0) {
          clock_gettime(CLOCK_MONOTONIC, &end);
          millsec = (end.tv_sec * 1000LL + end.tv_nsec / 1000000 ) - 
           	  (begin.tv_sec * 1000LL + begin.tv_nsec / 1000000);
          printf("(%d)(%d)(%d)(%4.2f)\n",data_sum,sum_read,sum_sent,data_sum/millsec/1000);fflush(stdout);
          memset(&begin,0,sizeof(begin));
          sum_sent=0;sum_read=0;
	}
      }
    }
    close(msg_fd_in);
  }

  close(fd_in);
  close(fd_out);
  unlink(NAME_IN);
}
