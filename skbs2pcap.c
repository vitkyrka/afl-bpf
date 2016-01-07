#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <stdint.h>
#include <pcap/pcap.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;

struct net_device {
	unsigned int dummy;
	unsigned int ifindex;		//  4
	unsigned short type;		//  4
};

struct rnd_state {
	int dummy;
};

typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;

struct sk_buff {
	int dummy;
	unsigned int len;		//  4
	unsigned int data_len;		//  8
	unsigned char *data;		// 12

	unsigned int network_header;	// 16
	unsigned int mac_header;	// 20
	unsigned char *head;		// 24
	unsigned char *tail;		// 28
	unsigned short protocol;	// 32
	unsigned short padding;
	struct net_device *dev;		// 36
	unsigned int mark;		// 40
	unsigned short dummy1;		// 44
	unsigned short queue_mapping;	// 46
	unsigned short padding1;	// 48
	unsigned int rxhash;		// 50
	u8 __pkt_type_offset[0];
	u32 pkt_type;
	u32 vlan_present;
	u16 vlan_tci;
	u16 vlan_proto;
	u32 priority;
	u32 ingress_ifindex;
	u32 ifindex;
	u32 tc_index;
	u32 cb[5];
	u32 hash;
	u32 tc_classid;
	int ip_summed;
	int csum;
	int skb_iif;
} __attribute__((packed));

static struct sk_buff skbs[] = {
#include "skbs.h"
};

int main(int argc, char *argv[])
{
	pcap_t *handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
	pcap_dumper_t *dumper = pcap_dump_open(handle, "skbs.pcap");
	struct pcap_pkthdr pcap_hdr;
	int i;

	for (i = 0; i < ARRAY_SIZE(skbs); i++) {
		struct sk_buff *skb = &skbs[i];

		pcap_hdr.caplen = skb->len;
		pcap_hdr.len = pcap_hdr.caplen;

		pcap_dump((u_char *)dumper, &pcap_hdr, skb->data);
	}
	pcap_dump_close(dumper);

	return 0;
}

