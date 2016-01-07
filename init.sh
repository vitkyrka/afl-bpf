#!/bin/sh -e

LINK='
arch/arm/net/bpf_jit_32.h
arch/arm/net/bpf_jit_32.c
arch/arm64/net/bpf_jit.h
arch/arm64/net/bpf_jit_comp.c
arch/arm64/include/asm/insn.h
arch/arm64/kernel/insn.c
arch/x86/net/bpf_jit_comp.c
arch/x86/net/bpf_jit.S
include/uapi/linux/bpf.h
include/uapi/linux/bpf_common.h
include/uapi/linux/filter.h
include/uapi/linux/byteorder/little_endian.h
include/uapi/linux/byteorder/big_endian.h
include/linux/byteorder/generic.h
include/linux/byteorder/big_endian.h
include/linux/byteorder/little_endian.h
include/linux/filter.h
include/linux/bpf.h
kernel/bpf/core.c
net/core/filter.c
'

DUMMY='
include/linux/atomic.h
include/linux/bitops.h
include/linux/slab.h
include/linux/gfp.h
include/linux/if.h
include/linux/inet.h
include/linux/netlink.h
include/linux/compat.h
include/linux/bug.h
include/linux/smp.h
include/linux/spinlock.h
include/linux/stop_machine.h
include/linux/uaccess.h
include/linux/skbuff.h
include/linux/linkage.h
include/linux/ratelimit.h
include/linux/mm.h
include/linux/module.h
include/linux/moduleloader.h
include/linux/printk.h
include/linux/timer.h
include/linux/irqflags.h
include/linux/file.h
include/linux/compiler.h
include/linux/vmalloc.h
include/linux/workqueue.h
include/net/ip.h
include/net/netlink.h
include/net/flow_dissector.h
include/net/protocol.h
include/net/cls_cgroup.h
include/net/dst.h
include/net/dst_metadata.h
include/net/sch_generic.h
include/net/sock.h
include/asm/cacheflush.h
include/asm/cmpxchg.h
include/asm/barrier.h
include/asm/opcodes.h
include/asm/hwcap.h
include/asm/fixmap.h
include/asm/unaligned.h
include/asm/uaccess.h
include/asm/debug-monitors.h
'

LINUX=$1

[ -d $LINUX ] || {
	echo usage $0 PATH-TO-KERNEL-SOURCE
	exit 1
}

mkdir -p include/asm
cp $LINUX/include/asm-generic/atomic.h include/asm/atomic.h

for f in $LINK; do
	mkdir -p $(dirname $f)
	rm -f $f
	ln -s $LINUX/$f $f
done

for f in $DUMMY; do
	mkdir -p $(dirname $f)
	rm -f $f
	touch $f
done

cd $LINUX
patch -p1 < $OLDPWD/kernel.patch
