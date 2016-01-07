#include <linux/filter.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	struct sock_filter *filter;
	struct stat statbuf;
	unsigned int num, realnum;
	int fd;
	int ret;
	int i;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "open");

	ret = fstat(fd, &statbuf);
	if (ret < 0)
		err(1, "stat");

	filter = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE,
		      fd, 0);
	if (filter == MAP_FAILED)
		err(1, "mmap");

	num = statbuf.st_size / sizeof(struct sock_filter);
	realnum = num;

	switch (filter[num - 1].code) {
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_A:
		break;

	default:
		num++;
		break;
	}

	printf("load bpf %u,", num);

	for (i = 0; i < realnum; i++) {
		struct sock_filter *f = &filter[i];
		printf("%u %u %u %u,", f->code, f->jt, f->jf, f->k);
	}

	if (num != realnum)
		printf("%u %u %u %u,", BPF_RET | BPF_A, 0, 0, 0);

	printf("\n");
	printf("load pcap skbs.pcap\n");
	printf("disassemble\n");

	for (i = 0; i < num; i++) {
		printf("step\n");
	}

	close(fd);

	return 0;
}
