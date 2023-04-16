#include <stdint.h>

// from  <net/ieee80211_radiotap.h>
#define IEEE80211_RADIOTAP_TX_FLAGS	15
#define IEEE80211_RADIOTAP_F_TX_NOACK	0x0008
#define IEEE80211_RADIOTAP_MCS_HAVE_MCS	0x02
#define IEEE80211_RADIOTAP_MCS_BW_20	0

static const uint8_t radiotap_hdr[] = {
  0x00, 0x00, // <-- radiotap version + pad byte
  0x0b, 0x00, // <- radiotap header length
  0x04, 0x0c, 0x00, 0x00, // <-- bitmap
  0x87, // 0x0c 0x48 0x60 0x6c  (rate in 500kHz units)
  0x0c, //<-- tx power
  0x01 //<-- antenna
//      MCS_KNOWN , MCS_FLAGS, MCS_INDEX // bitmap, flags, mcs_index
};
/*
0x00, 0x00, // <-- radiotap version
0x16, 0x00, // <- radiotap header length
0x00, 0x80, 0x20, 0x00, // <-- radiotap present flags: RADIOTAP_TX_FLAGS + RADIOTAP_VHT
0x08, 0x00, // RADIOTAP_F_TX_NOACK
*/
int main(int argc, char *argv[]) {
}
