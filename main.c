#include <stdio.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include "compat.h"

#define SKB_MAX 4096

extern u32 bpf_emit_size;
static bool debug;

static struct sk_buff skbs[] = {
#include "skbs.h"
};

static inline ssize_t read_all(int fd, void *buf, size_t len)
{
	size_t left = len;

	while (left) {
		ssize_t bytes = read(fd, buf, left);

		if (bytes < 0)
			return bytes;
		if (bytes == 0)
			break;

		left -= bytes;
		buf += bytes;
	}

	return len - left;
}

static u64 run_jit(struct bpf_prog *fp)
{
	u64 retjit = 0xdead;
#ifdef __BPF_TEST_HOST
	int sock;
	char buf[100];
	ssize_t bytes;
	struct sockaddr_un addr = {0};
	int ret;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		err(1, "socket");

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/runner");

	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		warn("connect");
		abort();
	}

	bytes = write(sock, &bpf_emit_size, sizeof(bpf_emit_size));
	if (bytes != sizeof(bpf_emit_size))
		err(1, "write");
	bytes = write(sock, fp->bpf_func, bpf_emit_size);
	if (bytes != bpf_emit_size)
		err(1, "write");

	shutdown(sock, SHUT_WR);

	bytes = read_all(sock, buf, sizeof(buf) - 1);
	if (bytes <= 0) {
		warn("read from child: %zd\n", bytes);
		abort();
	}
	buf[bytes] = '\0';
	if (debug)
		printf("read: %s\n", buf);
	if (sscanf(buf, "retjit %" PRIx64 "\n", &retjit) != 1) {
		warn("sscanf");
		abort();
	}

	close(sock);
#else
	int i;

	retjit = 0;
	for (i = 0; i < ARRAY_SIZE(skbs); i++) {
		struct sk_buff *skb = &skbs[i];
		u32 thisret;

		thisret = BPF_PROG_RUN(fp, skb);
		retjit += thisret;

		if (debug)
			printf("skb %d retjit %x\n", i, thisret);
	}
#endif

	return retjit;
}

struct sock_filter filter[4095];

int main(int argc, char *argv[])
{
	struct bpf_prog *intfp, *jitfp;
	struct sock_fprog_kern fprog;
	int ret;
	ssize_t n;
	u64 retinterp = 0, retjit;
	int i;

	if (argc > 1)
		debug = true;

	n = read(0, filter, sizeof(filter));
	if (n <= 0)
		err(1, "fread");

	fprog.filter = filter;
	fprog.len = n / sizeof(struct sock_filter);

	switch (filter[fprog.len - 1].code) {
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_A:
		break;

	default:
		filter[fprog.len].code = BPF_RET | BPF_A;
		fprog.len++;
		break;
	}

	bpf_jit_enable = 0;

	ret = bpf_prog_create(&intfp, &fprog);
	if (ret < 0)
		errx(1, "bpf_prog_create: %d\n", ret);

	bpf_jit_enable = debug ? 2 : 1;

	ret = bpf_prog_create(&jitfp, &fprog);
	if (ret < 0)
		errx(1, "bpf_prog_create: %d\n", ret);

	if (!jitfp->jited)
		errx(1, "cannot jit");

	retinterp = 0;
	for (i = 0; i < ARRAY_SIZE(skbs); i++) {
		struct sk_buff *skb = &skbs[i];
		u32 thisret;

		thisret = BPF_PROG_RUN(intfp, skb);
		retinterp += thisret;

		if (debug)
			printf("skb %d retinterp %x\n", i, thisret);
	}

	if (debug)
		printf("retinterp: %" PRIx64 "\n", retinterp);

	retjit = run_jit(jitfp);
	if (debug)
		printf("retjit: %" PRIx64 "\n", retjit);

	if (retinterp != retjit) {
		printf("-ERROR different rets\n");
		abort();
		return 1;
	}

	return 0;
}
