#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#define NAME_IN  "/tmp/socket2"
#define NAME_OUT  "/tmp/socket3"


#define MAX_PACKET_SIZE 10

/*
time dd if=/dev/urandom of=/dev/shm/data.dump bs=1M count=1024

DATAGRAM
socat "SYSTEM:dd if=/dev/shm/data.dump bs=1 count=1" UNIX-SEND:/tmp/socket2

option 1
--------
DATAGRAM -> STREAM
./sending


option 2
--------
socat UNIX-RECVFROM:/tmp/socket2 - | hexdump -C

*/
/*
socat -x -d UNIX-RECVFROM:socket -
echo 'test' | socat - UNIX-SEND:socket
*/


int main(int argc, char **argv) {

  int fd_in = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct sockaddr_un name_in;
  name_in.sun_family = AF_UNIX;
  strcpy(name_in.sun_path, NAME_IN);
  int ret = bind(fd_in, (struct sockaddr *) &name_in, sizeof(struct sockaddr_un));
  printf("bind ret=%d errno=%d\n",ret,errno);fflush(stdout);

  int fd_out = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un name_out;
  name_out.sun_family = AF_UNIX;
  strcpy(name_out.sun_path, NAME_OUT);

  char buf[MAX_PACKET_SIZE];
  memset(buf,0x58,sizeof(buf));

  struct timespec begin;

  int data_read;
  int data_sent;

  while (true) {

    data_read = recv(fd_in, buf, sizeof(buf), 0);  
    printf("data_read=%d errno=%d\n",data_read, errno);fflush(stdout);

    if (data_read > 0) {
       
      data_sent = sendto(fd_out,buf,sizeof(buf),0,&name_out,sizeof(struct sockaddr_un));
      printf("data_sent=%d errno=%d\n",data_sent, errno);fflush(stdout);

/*
  if (sendto(sock, buf, sizeof(buf), 0,
      &name, sizeof(struct sockaddr_un)) < 0) {
      perror("sending datagram message");
  }
*/
      clock_gettime(CLOCK_MONOTONIC, &begin);
      double milliseconds = begin.tv_sec * 1000LL + begin.tv_nsec / 1000000;
      printf("(%f)",milliseconds);
    
      printf("(%d)",MAX_PACKET_SIZE);
      for (int i=0;i<MAX_PACKET_SIZE;i++) printf("%u ",buf[i]);
      printf("\n");
    }
  }

  close(fd_in);
  close(fd_out);
}
