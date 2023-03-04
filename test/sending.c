#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#define NAME_IN  "/tmp/socket2"
#define NAME_OUT  "/tmp/socket3"


#define MAX_SIZE_OUT 2048
//#define MAX_SIZE_OUT 8192
#define MAX_SIZE_IN 8192


/*
time dd if=/dev/urandom of=/dev/shm/data.dump bs=1M count=1024

DATAGRAM
socat "SYSTEM:dd if=/dev/shm/data.dump bs=1 count=1" UNIX-SEND:/tmp/socket2


option 1
--------
DATAGRAM -> STREAM
./sending

STREAM
rm /tmp/socket3
socat UNIX-LISTEN:/tmp/socket3 - | hexdump -C


option 2
--------
DATAGRAM
socat -x -d UNIX-RECV:/tmp/socket2 - | hexdump
(start receiving at 16 bytes)
or
socat -x -d UNIX-RECVFROM:/tmp/socket2 - | hexdump
(no range limits)

*/


int main(int argc, char **argv) {

  int fd_in = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct sockaddr_un name_in;
  name_in.sun_family = AF_UNIX;
  strcpy(name_in.sun_path, NAME_IN);
  int ret = bind(fd_in, (struct sockaddr *) &name_in, sizeof(struct sockaddr_un));

  int fd_out = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un name_out;
  name_out.sun_family = AF_UNIX;
  strcpy(name_out.sun_path, NAME_OUT);
  ret = connect(fd_out,&name_out,sizeof(struct sockaddr_un));

  char *ptr;
  char buf[MAX_SIZE_IN];
  memset(buf,0x58,sizeof(buf));

  struct timespec begin,end;
  memset(&begin,0,sizeof(begin));

  int data_avail;
  int data_read;
  int data_sent;
  int data_sum=0;
  double millsec;
  int sum_sent=0,sum_read=0;

  while (true) {
    ioctl(fd_in,FIONREAD,&data_avail);
    usleep(1);
    if (((begin.tv_sec+begin.tv_nsec) != 0)&&(data_avail==0)) {
      clock_gettime(CLOCK_MONOTONIC, &end);
      millsec = (end.tv_sec * 1000LL + end.tv_nsec / 1000000 ) - 
	        (begin.tv_sec * 1000LL + begin.tv_nsec / 1000000);
      printf("(%d)(%d)(%d)(%4.2f)\n",data_sum,sum_read,sum_sent,data_sum/millsec/1000);fflush(stdout);
      memset(&begin,0,sizeof(begin));
      sum_sent=0;sum_read=0;
    }
	    
    data_read = recv(fd_in, buf, sizeof(buf), 0);  
    if ((begin.tv_sec+begin.tv_nsec) == 0) clock_gettime(CLOCK_MONOTONIC, &begin);
    data_sum += data_read;
    sum_read ++;
    ptr = buf; 
    while (data_read > 0) {
      data_sent = send(fd_out,ptr,MAX_SIZE_OUT,0);
      data_read -= data_sent; 
      ptr += data_sent; 
      sum_sent ++;
      
//      printf("(");
//      for (int i=0;i<data_read;i++) printf("%02x  ",buf[i] & 0xff);
//      printf(")\n");
    }
  }

  close(fd_in);
  close(fd_out);
}
