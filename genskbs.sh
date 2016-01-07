#!/bin/sh -e

genone() {
	size=$1
	data=$(dd if=/dev/urandom bs=1 count=$size 2>/dev/null | xxd -i)

	cat<<EOF
		{
			.len = $size,
			.data = (unsigned char []) {
			    $data,
			},
			.queue_mapping = 0xdead,
			.protocol = 0xabcd,
			.mark = 0x12345678,
			.rxhash = 0xcafebabe,
			.dev = (struct net_device []) {
				{
					.ifindex = 0xdebeefed,
				},
			},
		},
EOF
}

i=1
while [ $i -lt 30 ]; do
	size=$(printf '%d' $(dd if=/dev/urandom bs=1 count=1 2>/dev/null | xxd -i))
	genone $(($size * $i))
	i=$((i + 1))
done
