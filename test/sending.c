#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


#define NAME "socket"

/*
socat -x -d UNIX-RECVFROM:socket -
echo 'test' | socat - UNIX-SEND:socket
*/

const int  buf_size = 6;

int main(int argc, char **argv) {

  int sock = socket(AF_UNIX, SOCK_DGRAM, 0);

  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NAME);

  char buf[buf_size];
  memset(buf,3,buf_size);

  struct timespec begin;

  if (sendto(sock, &buf, sizeof(buf), 0,
      &name, sizeof(struct sockaddr_un)) < 0) {
      perror("sending datagram message");
  }

  clock_gettime(CLOCK_REALTIME, &begin);
  double nanoseconds = begin.tv_sec * 1e9 + begin.tv_sec;
  printf("(%f)",nanoseconds);

  printf("(%d)",buf_size);
  for (int i=0;i<buf_size;i++) printf("%u ",buf[i]);
  printf("\n");

  close(sock);
}
