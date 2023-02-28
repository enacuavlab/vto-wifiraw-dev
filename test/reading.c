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

#define NAME "socket"

/*
socat -x -d UNIX-RECVFROM:socket - 
echo 'test' | socat - UNIX-SEND:socket
*/

const int  buf_size = 10;

int main(int argc, char **argv) {

  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NAME);
  bind(fd, (struct sockaddr *) &name, sizeof(struct sockaddr_un));

  fd_set readset;

  char buf[buf_size];
  memset(buf,1,buf_size);

  int buf_available = buf_size;
  int data_available=0;
  int data_toread=0;
  int data_read=0;

  struct timespec begin;

  char *ptr = buf;

  while (buf_available>0) {

    FD_ZERO(&readset);
    FD_SET(fd, &readset);

    int n = select(fd+1, &readset, NULL, NULL, NULL);

    if(n == 0) break;
    if(FD_ISSET(fd, &readset)) {
      ioctl(fd,FIONREAD,&data_available);
      if (data_available>0) {

        if (data_available <= buf_available) data_toread = data_available; 
        if (data_available > buf_available) data_toread = buf_available - data_available; 
	if (data_toread > 0) {
  	  data_read = recv(fd, ptr, data_toread, 0);

	  clock_gettime(CLOCK_REALTIME, &begin);
          double nanoseconds = begin.tv_sec * 1e9 + begin.tv_sec;
          printf("(%f)",nanoseconds);

          printf("(%d)(%d)",data_toread,data_read);fflush(stdout);
          for (int i=0;i<buf_size;i++) printf("%u ",buf[i]);
          printf("\n");
 
	} 

        buf_available = buf_available - data_read;
  	if (buf_available>0) ptr = ptr + data_read;
      }
    }
  }
  close(fd);
  unlink(NAME);
}
