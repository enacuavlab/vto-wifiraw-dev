#include <stdint.h>

// from  <net/ieee80211_radiotap.h>
static uint8_t radiotap_header[]  __attribute__((unused)) = {
    0x00, 0x00,  // radiotap version
    0x0d, 0x00,  // radiotap header length
    0x00, 0x80,  // radiotap present flags: 0x8000 = ( 1 << IEEE80211_RADIOTAP_TX_FLAGS(15) ) 
    0x08, 0x00,  // radiotap present flags continue : 0x80000 |= ( 1 << IEEE80211_RADIOTAP_MCS(19) )
    0x08, 0x00,  // contents: IEEE80211_RADIOTAP_F_TX_NOACK(0x08)
    0x16,        // mcs_known: 0x16 = IEEE80211_RADIOTAP_MCS_HAVE_BW(0x01) | IEEE80211_RADIOTAP_MCS_HAVE_MCS(0x02) IEEE80211_RADIOTAP_MCS_HAVE_GI(0x04)
    0x04,        // mcs_flags: |= IEEE80211_RADIOTAP_MCS_BW_20(0) |= IEEE80211_RADIOTAP_MCS_SGI(0x04);												    
    0x01         // mcs_index
};


int main(int argc, char *argv[]) {

}
