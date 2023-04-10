Channel 140
----------

sudo ./test_capt_once $node

sudo ./test_inject_once $node


OK for legacy bitrate setting 0x48 or 0x60

OK for no legacy: (https://mcsindex.com/)
- #define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20)
  #define MCS_INDEX  1 -> bad
 ...
  #define MCS_INDEX  7 -> good

