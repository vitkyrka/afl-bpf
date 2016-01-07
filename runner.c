#include <stdio.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <inttypes.h>

#include "compat.h"

extern int bpf_run(struct sock_filter *f, int flen, unsigned int *insns);

static bool debug;

static struct sk_buff skbs[] = {
#include "skbs.h"
};

int handle(int conn)
{
	int i;
	u32 len;
	u64 retjit;
	size_t n;
	u32 *bpf_run_buffer;
	unsigned int		(*bpf_func)(const struct sk_buff *skb,
					    const struct bpf_insn *filter);
	FILE *fp;

	fp = fdopen(conn, "a+");
	if (!fp)
		err(1, "fdopen");

	n = fread(&len, sizeof(len), 1, fp);
	if (n < 1)
	    err(1, "fread");

	if (debug)
		fprintf(stderr, "insns len: %u\n", len);

	bpf_run_buffer = malloc(len);
	if (!bpf_run_buffer)
		err(1, "malloc");

	n = fread(bpf_run_buffer, 1, len, fp);
	if (n < len)
		err(1, "fread");

	if (debug)
		fprintf(stderr, "read %zu insn\n", n);

	if (debug) {
		int j;

		for (j = 0; j < 16; j++)
			fprintf(stderr, "insn[%d] = %x\n", j, bpf_run_buffer[j]);
	}

	bpf_func = (void *) bpf_run_buffer;

	retjit = 0;
	for (i = 0; i < ARRAY_SIZE(skbs); i++) {
		struct sk_buff *skb = &skbs[i];
		if (debug)
			printf("calling %p\n", bpf_func);
		retjit += bpf_func(skb, NULL);
	}

	if (debug)
		fprintf(stderr, "retjit 0x%" PRIx64 " \n",  retjit);

	fprintf(fp, "retjit 0x%" PRIx64 "\n",  retjit);
	fclose(fp);

	return 0;
}

int main(int argc, char *argv[])
{
	int sock, conn;
	int ret;
	struct sockaddr_un addr = {0};
	struct sockaddr_un clientaddr;
	socklen_t addrsz;

	if (argc > 1)
		debug = true;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		err(1, "socket");

	signal(SIGCHLD, SIG_IGN);

	unlink("/tmp/runner");
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/runner");

	ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0)
		err(1, "bind");

	ret = listen(sock, 50);
	if (ret < 0)
		err(1, "listen");

	while (1) {
		addrsz = sizeof(struct sockaddr_un);
		ret = accept(sock, (struct sockaddr *) &clientaddr,
			     &addrsz);
		if (ret < 0)
			err(1, "accept");

		conn = ret;

		ret = fork();
		if (ret < 0)
			err(1, "fork");

		if (ret == 0) {
			handle(conn);
			close(conn);
			exit(0);
		}

		close(conn);
	}

	return 0;
}
