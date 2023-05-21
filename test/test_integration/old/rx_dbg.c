#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DATA_SIZE 1400
#define UDP_SIZE 65507

/*****************************************************************************/
int main(int argc, char *argv[]) {

  setpriority(PRIO_PROCESS, 0, -10);

  char addr_str[20] = "127.0.0.1";

  uint16_t fd_in, port_in = 5500;
  if (-1 == (fd_in=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  struct sockaddr_in addr_in;
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(port_in);
  addr_in.sin_addr.s_addr = inet_addr(addr_str);
  if (-1 == bind(fd_in, (struct sockaddr *)&addr_in, sizeof(addr_in))) exit(-1);

  uint16_t fd_out, port_out = 6000;
  struct sockaddr_in addr_out;
  if (-1 == (fd_out=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) exit(-1);
  addr_out.sin_family = AF_INET;
  addr_out.sin_port = htons(port_out);
  addr_out.sin_addr.s_addr = inet_addr(addr_str);

  ssize_t len_in, len_out;
  uint16_t len = 0;
  uint8_t udp_in[DATA_SIZE];
  uint8_t udp_out[UDP_SIZE];

  for(;;) {
    len_in = read(fd_in, udp_in, DATA_SIZE);
    printf("read(%ld)\n",len_in);
    if (len_in > 0) {
      memcpy(udp_out + len , udp_in, len_in);
      len += len_in;
      if (len_in < DATA_SIZE) {
        len_out = sendto(fd_out, udp_out, len, 0, (struct sockaddr *)&addr_out, sizeof(struct sockaddr));
        printf("sendto(%ld)\n",len_out);
	len = 0;
      }
    }
  }
}
