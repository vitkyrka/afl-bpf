#include "compat.h"

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
	if ((int)skb->len - offset < len)
		return -1;

	switch (len) {
	case 1:
		*(unsigned char *)to = *(unsigned char *)(skb->data + offset);
		break;
	case 2:
		*(unsigned short *)to = *(unsigned short *)(skb->data + offset);
		break;
	case 4:
		*(unsigned int *)to = *(unsigned int *)(skb->data + offset);
		break;
	}

	return 0;
}

int skb_store_bits(struct sk_buff *skb, int offset, const void *from, int len)
{
	int start = skb_headlen(skb);
	int copy;

	if (offset > (int)skb->len - len)
		goto fault;

	if ((copy = start - offset) > 0) {
		if (copy > len)
			copy = len;
		memcpy(skb->data + offset, from, copy);
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		from += copy;
	}

	if (!len)
		return 0;

fault:
	return -EFAULT;
}
