#include <stdlib.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <errno.h>

#define IEEE80211_RADIOTAP_MCS_SGI 0x04

#define BUF_SIZE_MAX   (1536)
#define BUF_SIZE_TOTAL (BUF_SIZE_MAX+1) // +1 in case the sprintf insert the last 0

/* wifi bitrate to use in 500kHz units */
static const uint8_t uint8_taRatesToUse[] = {
	6*2,
	9*2,
	12*2,
	18*2,
	24*2,
	36*2,
	48*2,
	54*2
};

/* this is the template radiotap header we send packets out with */
static const uint8_t uint8_taRadiotapHeader[] = 
{
	0x00, 0x00, // <-- radiotap version
	0x1c, 0x00, // <- radiotap header length
	0x6f, 0x08, 0x08, 0x00, // <-- bitmap
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
	0x00, // <-- flags (Offset +0x10)
	0x6c, // <-- rate (0ffset +0x11)
	0x71, 0x09, 0xc0, 0x00, // <-- channel
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna
	0x02, 0x00, 0x0f,  // <-- MCS
};

#define	OFFSET_RATE 0x11
#define MCS_OFFSET 0x19
#define GI_OFFSET 0x1a
#define MCS_RATE_OFFSET 0x1b

static uint8_t ieee_hdr_data[] =
{
        0x08, 0x02, 0x00, 0x00,             // FC 0x0801. 0--subtype; 8--type&version; 02--toDS0 fromDS1 (data packet from DS to STA)
        0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // BSSID/MAC of AP
        0x66, 0x55, 0x44, 0x33, 0x22, 0x22, // Source address (STA)
        0x66, 0x55, 0x44, 0x33, 0x22, 0x33, // Destination address (another STA under the same AP)
        0x10, 0x86,                         // 0--fragment number; 0x861=2145--sequence number
};


int flagHelp = 0;

int main(int argc, char *argv[])
{
        uint8_t portId = 5;

	uint8_t buffer[BUF_SIZE_TOTAL], *ieee_hdr = ieee_hdr_data;
        uint8_t *pu8 = buffer;

	char szErrbuf[PCAP_ERRBUF_SIZE], hw_mode = 'n';
	int i, r, rate_index = 5, sgi_flag = 0, num_packets = 10000, payload_len = 1450, packet_size ,  nDelay = 400;
	pcap_t *ppcap = NULL;

	// open the interface in pcap
	szErrbuf[0] = '\0';
	ppcap = pcap_open_live(argv[optind], 800, 1, 20, szErrbuf);
	if (ppcap == NULL)
	{
		printf("Unable to open interface %s in pcap: %s\n", argv[optind], szErrbuf);
		return (1);
	}

	pcap_setnonblock(ppcap, 1, szErrbuf);

	packet_size = sizeof(uint8_taRadiotapHeader) +  sizeof(ieee_hdr_data) + payload_len;
	printf("mode = 802.11%c, rate index = %d, SHORT GI = %d, number of packets = %d and packet size = %d bytes, delay = %d usec\n", hw_mode, rate_index, sgi_flag, num_packets, packet_size, nDelay);
	printf("payload_len %d\n", payload_len);

	if (packet_size > BUF_SIZE_MAX) {
		printf("packet_size %d > %d! Quite\n", packet_size, BUF_SIZE_MAX);
		return(1);
	}

	memset(buffer, 0, sizeof (buffer));
	memcpy(buffer, uint8_taRadiotapHeader, sizeof (uint8_taRadiotapHeader));
	pu8 += sizeof(uint8_taRadiotapHeader);
	// Update radiotap header (i.e. hw_mode, rate, GI)
	if(hw_mode == 'g' || hw_mode == 'a')
	{
		buffer[OFFSET_RATE] = uint8_taRatesToUse[rate_index];
		buffer[MCS_OFFSET] = 0x00;
	}
	else
	{
		buffer[MCS_OFFSET] = 0x07;
		if(sgi_flag)
			buffer[GI_OFFSET] = IEEE80211_RADIOTAP_MCS_SGI;
		buffer[MCS_RATE_OFFSET] = rate_index;
	}
	ieee_hdr[9] = portId;
	memcpy(buffer + sizeof(uint8_taRadiotapHeader), ieee_hdr, sizeof(ieee_hdr_data));

	for(i = 1; i <= num_packets; i++)
	{
		r = pcap_inject(ppcap, buffer, packet_size);
		if (r != packet_size) {
			perror("Trouble injecting packet");
			return (1);
		}

		printf("number of packets sent = %d\r", i);
		fflush(stdout);

		if (nDelay)
			usleep(nDelay);
	}

	printf("\n");

	return (0);
}
