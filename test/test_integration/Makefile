#ROLE := BOARD_TELEM
#ROLE := BOARD
ROLE := GROUND

PROT := RAW

# DO NOT TOUCH BELOW THIS LINE
# ----------------------------

PROTFLAG :=
  ifneq ($(PROT),RAW)
    PROTFLAG += -DADDR_REMOTE_BOARD=\"192.168.3.2\"
    PROTFLAG += -DADDR_REMOTE_GROUND=\"192.168.3.1\"
  else
    PROTFLAG += -DRAW
  endif


ROLEFLAG :=
  ifeq ($(ROLE),GROUND)
    ROLEFLAG = -DROLE=0
 else ifeq ($(ROLE),BOARD)
    ROLEFLAG = -DROLE=1
 else ifeq ($(ROLE),BOARD_TELEM)
    ROLEFLAG = -DROLE=2
 endif


OSFLAG :=
  ifeq ($(ROLE),BOARD_TELEM)
    UNAME_R := $(shell uname -r)
    ifeq ($(UNAME_R),4.9.253-tegra)
      OSFLAG = -DUART=\"/dev/ttyTHS1\"
    else ifeq ($(UNAME_R),6.1.21-v8+)
      OSFLAG = -DUART=\"/dev/ttyAMA0\"
    endif
  endif

CPPFLAGS=-Wall -D _GNU_SOURCE -g

all: wfb #test_tun #  test_tv_tx test_tv_rx

%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS) $(OSFLAG) $(PROTFLAG) $(ROLEFLAG)

test_tun: wfb.o
test_tun: test_tun.o
test_tv_tx: test_tv_tx.o
test_tv_rx: test_tv_rx.o
	gcc -o $@ $^ $(LDFLAGS) $(CPPFLAGS)

clean:
	rm -f wfb test_tun test_tv_tx test_tv_rx *~ *.o
