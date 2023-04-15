#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>


/*****************************************************************************/
typedef struct {
  uint16_t seq;
  uint16_t len;
  uint64_t stp_n;
} pay_hdr_t;

/*****************************************************************************/
static const char wifi_hdr[] = {
  0x88, 0x00, 0x30, 0x00,             // frame type to match on receiver
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // port to be set and to match on receiver
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xc0, 0x20, 0x20, 0x00
};

static const uint8_t llc_hdr[] = {
  0xaa, 0xaa, 0x03,
  0x00, 0x00, 0x00,
  0x88, 0xb5
};

/*****************************************************************************/
//#define LEGACY
#ifdef LEGACY

static const uint8_t radiotap_hdr[] = {
  0x00, 0x00, // <-- radiotap version + pad byte
  0x0b, 0x00, // <- radiotap header length
  0x04, 0x0c, 0x00, 0x00, // <-- bitmap
  0x60, // <-- 0x60 rate (in 500kHz units)
  0x0c, //<-- tx power
  0x01 //<-- antenna
};

#else
// https://mcsindex.com/
#define IEEE80211_RADIOTAP_MCS_HAVE_BW    0x01
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS   0x02
#define IEEE80211_RADIOTAP_MCS_HAVE_GI    0x04
#define IEEE80211_RADIOTAP_MCS_HAVE_FMT   0x08

#define IEEE80211_RADIOTAP_MCS_BW_20    0
#define IEEE80211_RADIOTAP_MCS_BW_40    1
#define IEEE80211_RADIOTAP_MCS_BW_20L   2
#define IEEE80211_RADIOTAP_MCS_BW_20U   3
#define IEEE80211_RADIOTAP_MCS_SGI      0x04
#define IEEE80211_RADIOTAP_MCS_FMT_GF   0x08
#define IEEE80211_RADIOTAP_MCS_HAVE_FEC   0x10
#define IEEE80211_RADIOTAP_MCS_HAVE_STBC  0x20

#define IEEE80211_RADIOTAP_MCS_FEC_LDPC   0x10
#define IEEE80211_RADIOTAP_MCS_STBC_MASK  0x60
#define IEEE80211_RADIOTAP_MCS_STBC_1  1
#define IEEE80211_RADIOTAP_MCS_STBC_2  2
#define IEEE80211_RADIOTAP_MCS_STBC_3  3
#define IEEE80211_RADIOTAP_MCS_STBC_SHIFT 5

#define MCS_KNOWN (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)

// offset of MCS_FLAGS and MCS index
//#define MCS_FLAGS_OFF 11
//#define MCS_IDX_OFF 12

// For MCS#1 -- QPSK 1/2 20MHz long GI + STBC
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT))

// for MCS#1 -- QPSK 1/2 20MHz long GI without STBC
#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20)
#define MCS_INDEX  1

// for stbc + ldpc: https://en.wikipedia.org/wiki/Space%E2%80%93time_block_code
//#define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20 | (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT) | IEEE80211_RADIOTAP_MCS_FEC_LDPC)
//#define MCS_INDEX  1

static uint8_t radiotap_hdr[]  __attribute__((unused)) = {
    0x00, 0x00, // <-- radiotap version
    0x0d, 0x00, // <- radiotap header length
    0x00, 0x80, 0x08, 0x00, // <-- radiotap present flags:  RADIOTAP_TX_FLAGS + RADIOTAP_MCS
    0x08, 0x00,  // RADIOTAP_F_TX_NOACK
    MCS_KNOWN , MCS_FLAGS, MCS_INDEX // bitmap, flags, mcs_index
};

#endif /* LEGACY */

