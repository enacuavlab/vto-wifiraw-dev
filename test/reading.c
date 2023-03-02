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

#define NAME_IN  "socket1"
#define NAME_OUT "socket2"

/*
SOCK_DGRAM to convert to SOCK_STREAM
time socat OPEN:/dev/urandom,readbytes=12 UNIX-SENDTO:socket1

SOCK_DGRAM
time socat -x -d UNIX-RECVFROM:socket2 - | hexdump -C

socat -x -d UNIX-RECVFROM:socket - 
echo 'test' | socat - UNIX-SEND:socket
*/

const int  buf_size = 10;

int main(int argc, char **argv) {

//  int fd_in = socket(AF_UNIX, SOCK_DGRAM, 0);
  int fd_in = socket(AF_UNIX, SOCK_STREAM, 0); // in order to enable partial receive
  struct sockaddr_un name_in;
  name_in.sun_family = AF_UNIX;
  strcpy(name_in.sun_path, NAME_IN);
  bind(fd_in, (struct sockaddr *) &name_in, sizeof(struct sockaddr_un));
  
  int fd_out = socket(AF_UNIX, SOCK_DGRAM, 0);
  struct sockaddr_un name_out;
  name_out.sun_family = AF_UNIX;
  strcpy(name_out.sun_path, NAME_OUT);


  fd_set readset;

  char buf[buf_size];
  memset(buf,0x59,buf_size);

  int buf_available = buf_size;
  int data_available=0;
  int data_toread=0;
  int data_read=0;

  struct timespec begin;
  memset(&begin, 0, sizeof(begin));

  char *ptr = buf;

  while (true) {

    FD_ZERO(&readset);
    FD_SET(fd_in, &readset);

    int n = select(fd_in+1, &readset, NULL, NULL, NULL);

    if(n == 0) break;
    if(FD_ISSET(fd_in, &readset)) {
      ioctl(fd_in,FIONREAD,&data_available);

      while (data_available>0) {

	if (buf_available > 0) {

	  printf("data_available (%d)\n",data_available);

          if (data_available >= buf_available) data_toread = buf_available;
	  else data_toread = buf_available - data_available; 

	  if (data_toread > data_available) { // set padding condition
	
	     data_toread = data_available;

	     ptr = buf;
	     buf_available = data_toread;
	     data_available = data_toread;

	  } 

          data_read = recv(fd_in, ptr, data_toread, 0);
	  printf("data_read = %d\n",data_read);fflush(stdout);
          if (begin.tv_sec==0) clock_gettime(CLOCK_REALTIME, &begin);

	  ptr += data_read;
          buf_available  -= data_read;
          data_available -= data_read;

	} 
	
	if (buf_available == 0) {

          int ret = sendto(fd_out, &buf, data_read, 0, &name_out, sizeof(struct sockaddr_un));

	  printf("(");
          for (int i=0;i<data_read;i++) printf("%02x  ",buf[i] & 0xff);
	  printf(")\n");

	  buf_available = buf_size;
	  memset(&buf,0x57,sizeof(buf));

	  if (ret < 0) exit(-1);
	}
      }
    }
  }

/*
	  clock_gettime(CLOCK_REALTIME, &begin);
          double nanoseconds = begin.tv_sec * 1e9 + begin.tv_sec;
          printf("(%f)",nanoseconds);

          printf("(%d)(%d)",data_toread,data_read);fflush(stdout);
          for (int i=0;i<buf_size;i++) printf("%u ",buf[i]);
          printf("\n");
*/ 
  close(fd_in);
  close(fd_out);
  unlink(NAME_IN);
}
