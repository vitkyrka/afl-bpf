/*
 * Hodgepodge of various kernel headers and macros.  The same license as the
 * Linux kernel applies.
 */
#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define CONFIG_BPF_JIT

#define __user
#define __force
#define __must_check
#define likely(x) (x)
#define unlikely(x) (x)
#define BUG_ON(x) do {		\
	if (x) abort(); 	\
} while(0)
#define WARN_ON BUG_ON
#define READ_ONCE(x) (x)
#define __maybe_unused

#if defined(__aarch64__) || defined(__x86_64__)
#define BITS_PER_LONG 64
#elif defined(__arm__) || defined(__i386__)
#define BITS_PER_LONG 32
#else
#error define BITS_PER_LONG
#endif

#define IS_ENABLED(x) 0
#define probe_kernel_write(addr, val, sz) \
({ (void)addr; -EFAULT; })
#define probe_kernel_read(val, addr, insp) \
({ -EFAULT; })
#define DEFINE_RAW_SPINLOCK(x) int x __attribute__((unused))
#define raw_spin_lock_irqsave(lock, flags) ((void)(flags))
#define raw_spin_unlock_irqrestore(lock, flags) ((void) (flags))
#define virt_to_page(addr) (NULL)
#define vmalloc_to_page(addr) (NULL)
#define core_kernel_text(x) 1
#define page_to_phys(x) 0
#define set_fixmap_offset(f, addr) (addr)

#define FIX_TEXT_POKE0 0
#define clear_fixmap(x)
#define cpu_relax()
#define isb()
#define stop_machine(cb, data, mask) \
({ (void) data; (void) cb;  -EINVAL; })
#define num_online_cpus() 1
#define kick_all_cpus_sync()

typedef int mm_segment_t;
#define KERNEL_DS	0
#define get_fs()	0
#define set_fs(x)	((void)(x))

#define barrier() __asm__ volatile ("" ::: "memory")

#define skb_pfmemalloc(skb) 0
#define sock_flag(sk, flag) 0
#define security_sock_rcv_skb(sk, skb) 0
#define rcu_dereference(x) x
#define pskb_trim(skb, pkt_len) 0
#define rcu_read_lock()
#define rcu_read_unlock()
#define EXPORT_SYMBOL(x)
#define copy_from_user(a, b, c) c
#define copy_to_user(a, b, c) c
#define rcu_dereference_protected(x, y) x
#define rcu_assign_pointer(p, v) do {	\
	p = v;				\
} while (0)
#define lock_sock(sk)
#define release_sock(sk)
#define skb_cloned(skb)	false
#define skb_clone_writable(skb, len) 0
#define skb_postpull_rcsum(skb, ptr, len)
#define csum_add(csum, partial) csum
#define csum_replace2(ptr, from, to)
#define csum_replace4(ptr, from, to)
#define inet_proto_csum_replace2(ptr, skb, from, to, pseudo) ((void) (pseudo))
#define inet_proto_csum_replace4(ptr, skb, from, to, pseudo) ((void) (pseudo))
#define dev_net(x) x
#define dev_get_by_index_rcu(dev, idx) \
({ (void)dev, NULL; })
#ifndef AF_INET
#define AF_INET 2
#endif

#define skb_clone(skb, gfp) NULL
#define kfree_skb(skb)
#define skb_dst_drop(skb) ((void) (skb))
#define dst_hold(x)
#define skb_dst_set(skb, dst)
#define skb_tunnel_info(skb) &skb->info
#define skb_vlan_pop(skb) ((uintptr_t)skb | 0xbeef)
#define skb_vlan_push(skb, proto, tci) ((uintptr_t)skb | proto | tci | 0xcafe)
#define ip_tunnel_info_af(info) AF_INET
#define task_get_classid(skb) ((uintptr_t)skb | 0xdead)
#define dev_forward_skb(dev, skb) ((uintptr_t)skb | 0x1234)
#define dev_queue_xmit(skb) ((uintptr_t)skb | 0x5678)
#define skb_sender_cpu_clear(skb)
#define metadata_dst_alloc_percpu(x, gfp) NULL

#define late_initcall(x) static int x(void) __attribute__((unused))

# define trace_hardirq_context(p)	0
# define trace_softirq_context(p)	0
# define trace_hardirqs_enabled(p)	0
# define trace_softirqs_enabled(p)	0
# define trace_hardirq_enter()		do { } while (0)
# define trace_hardirq_exit()		do { } while (0)
# define lockdep_softirq_enter()	do { } while (0)
# define lockdep_softirq_exit()		do { } while (0)
# define INIT_TRACE_IRQFLAGS

# define stop_critical_timings() do { } while (0)
# define start_critical_timings() do { } while (0)

#define raw_local_irq_disable() do { } while (0)
#define raw_local_irq_enable() do { } while (0)
#define raw_local_irq_save(flags) ((flags) = 0)
#define raw_local_irq_restore(flags) do { (void) flags; } while (0)
#define raw_local_save_flags(flags) ((flags) = 0)
#define raw_irqs_disabled_flags(flags) do { } while (0)
#define raw_irqs_disabled() 0
#define raw_safe_halt()

#define local_irq_enable() do { } while (0)
#define local_irq_disable() do { } while (0)
#define local_irq_save(flags) ((flags) = 0)
#define local_irq_restore(flags) do { } while (0)
#define local_save_flags(flags)	((flags) = 0)
#define irqs_disabled() (1)
#define irqs_disabled_flags(flags) (0)
#define safe_halt() do { } while (0)

#define trace_lock_release(x, y)
#define trace_lock_acquire(a, b, c, d, e, f, g)

#define __used		__attribute__((__unused__))
#define WRITE_ONCE(x, val) x=(val)
#define RCU_INIT_POINTER(p, v) p=(v)

#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define pr_err printf
#define pr_info printf
#define pr_err_once printf
#define pr_info_once printf
#define pr_err_once printf

#define BUG() abort()

#define DUMP_PREFIX_OFFSET 0
#define PAGE_MASK (4095)

struct task_struct {
	char comm[10];
};

static struct task_struct __current = {
	.comm = "current",
};

#define current (&__current)
#define task_pid_nr(x)	1


#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

#define MAX_ERRNO	4095

#ifndef __ASSEMBLY__

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void * __must_check ERR_CAST(__force const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}

static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

/* Deprecated */
#define PTR_RET(p) PTR_ERR_OR_ZERO(p)
#endif

#include "uapi/linux/bpf_common.h"
#include "uapi/linux/bpf.h"
#include "uapi/linux/filter.h"

#define SOCK_MEMALLOC 0x0

typedef int gfp_t;
typedef struct {
	int counter;
} atomic_t;
typedef long long atomic64_t;

#define DEFINE_PER_CPU(a, b) a b
#define this_cpu_ptr(x) x
#define get_cpu_var(x) (x);

#define __GFP_HIGHMEM 	0
#define __GFP_ZERO	0
#define GFP_KERNEL	0
#define __GFP_NOWARN	0
#define PAGE_KERNEL	0
#define	PAGE_SIZE	4096

#define SOCK_FILTER_LOCKED	0
#define IP_TUNNEL_INFO_TX	0
#define TUNNEL_KEY	0

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define kmemcheck_annotate_bitfield(a, b)
#define kmemcheck_bitfield_begin(a)
#define kmemcheck_bitfield_end(a)

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

struct ip_tunnel_info {
	int tunnel_id;
	int mode;
	struct {
		int tun_id;
		int tun_flags;
		union {
			struct {
				int src;
				int dst;
			} ipv4;
		} u;
	} key;
};

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
	struct ip_tunnel_info info;
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

#define sysctl_optmem_max 0
#define CHECKSUM_COMPLETE 0

struct qdisc_skb_cb {
	int data[20];
	int tc_classid;
};

#define qdisc_skb_cb(skb) skb
#define QDISC_CB_PRIV_LEN	20

#if 0
struct sk_filter
{
	unsigned int len;
	struct sock_filter *insns;
	unsigned int		(*bpf_func)(const struct sk_buff *skb,
					    const struct sock_filter *filter);
	unsigned int gen_len;
};
#endif

#if 1
/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)					\
	do {							\
		((void)sizeof(char[1 - 2*!!(condition)]));	\
		if (condition) __build_bug_on_failed = 1;	\
	} while(0)
#endif
#endif

#define smp_wmb()
#define flush_icache_range(x, y)

#define INIT_WORK(a, b) b(a)
#define schedule_work(x)

static inline
void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, bool ascii)
{
#ifdef CONFIG_THUMB2_KERNEL
	const unsigned short *p = buf;
#else
	const unsigned int *p = buf;
#endif
	int i;

	printf("Code: ");

#ifdef CONFIG_THUMB2_KERNEL
	for (i = 0; i < len / 2; i++)
		printf("%04x ", *p++);

	printf("(%#04x) %#04x\n", 0, 0);
#else
	for (i = 0; i < len / 4; i++)
		printf("%08x ", *p++);

	printf("(%#010x)\n", 0);
#endif
}

#define printk printf
#define KERN_CONT ""
#define KERN_ERR ""
#define DUMP_PREFIX_ADDRESS 0

#define __read_mostly

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

struct work_struct {
	u8 data[10];
};
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define TC_ACT_REDIRECT 0

static inline void *module_alloc(size_t n)
{
	return malloc(n);
}

static inline void module_memfree(void *m)
{
	free(m);
}

static inline void *kcalloc(size_t n, size_t size, int gfp)
{
	return calloc(n, size);
}

static inline void kfree(void *m)
{
	free(m);
}

#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_IFINDEX 	8
#define SKF_AD_NLATTR	12
#define SKF_AD_NLATTR_NEST	16
#define SKF_AD_MARK 	20
#define SKF_AD_QUEUE	24
#define SKF_AD_HATYPE	28
#define SKF_AD_RXHASH	32
#define SKF_AD_CPU	36
// #define SKF_AD_MAX	40
#define SKF_NET_OFF   (-0x100000)
#define SKF_LL_OFF    (-0x200000)

#define ENOTSUPP	1

enum {
	BPF_S_RET_K = 1,
	BPF_S_RET_A,
	BPF_S_ALU_ADD_K,
	BPF_S_ALU_ADD_X,
	BPF_S_ALU_SUB_K,
	BPF_S_ALU_SUB_X,
	BPF_S_ALU_MUL_K,
	BPF_S_ALU_MUL_X,
	BPF_S_ALU_DIV_X,
	BPF_S_ALU_AND_K,
	BPF_S_ALU_AND_X,
	BPF_S_ALU_OR_K,
	BPF_S_ALU_OR_X,
	BPF_S_ALU_LSH_K,
	BPF_S_ALU_LSH_X,
	BPF_S_ALU_RSH_K,
	BPF_S_ALU_RSH_X,
	BPF_S_ALU_NEG,
	BPF_S_LD_W_ABS,
	BPF_S_LD_H_ABS,
	BPF_S_LD_B_ABS,
	BPF_S_LD_W_LEN,
	BPF_S_LD_W_IND,
	BPF_S_LD_H_IND,
	BPF_S_LD_B_IND,
	BPF_S_LD_IMM,
	BPF_S_LDX_W_LEN,
	BPF_S_LDX_B_MSH,
	BPF_S_LDX_IMM,
	BPF_S_MISC_TAX,
	BPF_S_MISC_TXA,
	BPF_S_ALU_DIV_K,
	BPF_S_LD_MEM,
	BPF_S_LDX_MEM,
	BPF_S_ST,
	BPF_S_STX,
	BPF_S_JMP_JA,
	BPF_S_JMP_JEQ_K,
	BPF_S_JMP_JEQ_X,
	BPF_S_JMP_JGE_K,
	BPF_S_JMP_JGE_X,
	BPF_S_JMP_JGT_K,
	BPF_S_JMP_JGT_X,
	BPF_S_JMP_JSET_K,
	BPF_S_JMP_JSET_X,
	/* Ancillary data */
	BPF_S_ANC_PROTOCOL,
	BPF_S_ANC_PKTTYPE,
	BPF_S_ANC_IFINDEX,
	BPF_S_ANC_NLATTR,
	BPF_S_ANC_NLATTR_NEST,
	BPF_S_ANC_MARK,
	BPF_S_ANC_QUEUE,
	BPF_S_ANC_HATYPE,
	BPF_S_ANC_RXHASH,
	BPF_S_ANC_CPU,
};

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->head + skb->mac_header;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return skb->tail;
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);
int skb_store_bits(struct sk_buff *skb, int offset, const void *from, int len);

static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
				       int len, void *buffer)
{
	int hlen = skb_headlen(skb);

	if (hlen - offset >= len)
		return skb->data + offset;

	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		return NULL;

	return buffer;
}

typedef uint64_t u64;
typedef int64_t s64;
#define __weak __attribute__((weak))
#define __init
#define noinline
#define __kprobes

#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008
#define SZ_16				0x00000010
#define SZ_32				0x00000020
#define SZ_64				0x00000040
#define SZ_128				0x00000080
#define SZ_256				0x00000100
#define SZ_512				0x00000200

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_8K				0x00002000
#define SZ_16K				0x00004000
#define SZ_32K				0x00008000
#define SZ_64K				0x00010000
#define SZ_128K				0x00020000
#define SZ_256K				0x00040000
#define SZ_512K				0x00080000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_4M				0x00400000
#define SZ_8M				0x00800000
#define SZ_16M				0x01000000
#define SZ_32M				0x02000000
#define SZ_64M				0x04000000
#define SZ_128M				0x08000000
#define SZ_256M				0x10000000
#define SZ_512M				0x20000000

#define SZ_1G				0x40000000
#define SZ_2G				0x80000000

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif

static inline u32 reciprocal_value(u32 k)
{
	u64 val = (1LL << 32) + (k - 1);
	val = val / k;
	return (u32)val;
}

static inline u32 reciprocal_divide(u32 A, u32 R)
{
	return (u32)(((u64)A * R) >> 32);
}

unsigned int sk_run_filter(const struct sk_buff *skb, const struct sock_filter *fentry);

extern int bpf_jit_enable;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct rcu_head {
	int dummy;
};

#define __aligned(x)
#include "linux/bpf.h"
#include "linux/filter.h"

struct sock {
	struct sk_filter *sk_filter;
	atomic_t sk_omem_alloc;
};

struct nlattr {
	int nla_len;
};

#define PKT_TYPE_MAX 7
#define VLAN_TAG_PRESENT 0x1000

#define ETH_P_8021Q 0
#define ETH_P_8021AD 0

struct metadata_dst {
	union {
		struct ip_tunnel_info tun_info;
	} u;
};

/* Not defined */
int cmpxchg(int *a, int b, int c);

#include <linux/byteorder/little_endian.h>
#include <linux/byteorder/generic.h>
#include <asm/atomic.h>

#define __percpu
#define capable(x) 1

#define nla_find_nested(nla, x) NULL
#define nla_find(nla, a, x) NULL
#define skb_is_nonlinear(skb) 0
static inline unsigned int __skb_get_poff(struct sk_buff *skb)
{
	return 0xdead;
}
#define skb_get_poff __skb_get_poff
#define raw_smp_processor_id() 0

#define WARN_RATELIMIT(a, b, c)

static inline void *kmalloc(size_t len, gfp_t flags)
{
	return calloc(len, 1);
}

static inline void *kmemdup(void *p, size_t len, gfp_t flags)
{
	void *newp = calloc(len, 1);

	if (newp)
		memcpy(newp, p, len);

	return newp;
}

static inline void *kzalloc(size_t len, gfp_t flags)
{
	return calloc(len, 1);
}

static inline void *kmalloc_array(int count, size_t len, gfp_t flags)
{
	return calloc(len, count);
}

static inline void *__vmalloc(size_t len, gfp_t flags, int other)
{
	return calloc(len, 1);
}

static inline void vfree(void *p)
{
}

static inline void atomic64_add(u64 what, atomic64_t *where)
{
	*where += what;
}

#define PKT_TYPE_OFFSET() 0

#define call_rcu(x, cb) cb(x)

# define do_div(n,base) ({					\
	uint32_t __base = (base);				\
	uint32_t __rem;						\
	__rem = ((uint64_t)(n)) % __base;			\
	(n) = ((uint64_t)(n)) / __base;				\
	__rem;							\
 })


#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64_rem - unsigned 64bit divide with 64bit divisor and remainder
 */
static inline u64 div64_u64_rem(u64 dividend, u64 divisor, u64 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_u64 - unsigned 64bit divide with 64bit divisor
 */
static inline u64 div64_u64(u64 dividend, u64 divisor)
{
	return dividend / divisor;
}

/**
 * div64_s64 - signed 64bit divide with 64bit divisor
 */
static inline s64 div64_s64(s64 dividend, s64 divisor)
{
	return dividend / divisor;
}

#define prandom_init_once(x)
#define prandom_u32_state(x) ((uintptr_t) (x))
#define prandom_u32(x) 0

#define put_cpu_var(x)

static inline u16 __get_unaligned_be16(const u8 *p)
{
	return p[0] << 8 | p[1];
}

static inline u32 __get_unaligned_be32(const u8 *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline u64 __get_unaligned_be64(const u8 *p)
{
	return (u64)__get_unaligned_be32(p) << 32 |
	       __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(u16 val, u8 *p)
{
	*p++ = val >> 8;
	*p++ = val;
}

static inline void __put_unaligned_be32(u32 val, u8 *p)
{
	__put_unaligned_be16(val >> 16, p);
	__put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(u64 val, u8 *p)
{
	__put_unaligned_be32(val >> 32, p);
	__put_unaligned_be32(val, p + 4);
}

static inline u16 get_unaligned_be16(const void *p)
{
	return __get_unaligned_be16((const u8 *)p);
}

static inline u32 get_unaligned_be32(const void *p)
{
	return __get_unaligned_be32((const u8 *)p);
}

static inline u64 get_unaligned_be64(const void *p)
{
	return __get_unaligned_be64((const u8 *)p);
}

static inline void put_unaligned_be16(u16 val, void *p)
{
	__put_unaligned_be16(val, p);
}

static inline void put_unaligned_be32(u32 val, void *p)
{
	__put_unaligned_be32(val, p);
}

static inline void put_unaligned_be64(u64 val, void *p)
{
	__put_unaligned_be64(val, p);
}


#define EXPORT_SYMBOL_GPL(x)

/* ARM */

#define elf_hwcap 0
#define HWCAP_THUMB	0
#define HWCAP_IDIVA	0
#define THREAD_SIZE	8192
#define set_memory_rw(x, y)
#define set_memory_ro(x, y)

#define __LINUX_ARM_ARCH__ 7

struct thread_info {
	int cpu;
};

#define __opcode_to_mem_arm(inst) inst

static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 ror32(__u32 word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static __always_inline int fls(int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

/* ARM64 */

#define FAULT_BRK_IMM			0x100
#define KGDB_DYN_DBG_BRK_IMM		0x400
#define KGDB_COMPILED_DBG_BRK_IMM	0x401
#define BUG_BRK_IMM			0x800

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON	0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 * Unlike kgdb, #imm16 value with unallocated handler is used for faulting.
 */
#define AARCH64_BREAK_FAULT	(AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))

#ifdef __BPF_TEST_HOST
extern u8 real__skb_get_pay_offset[];
extern u8 real__skb_get_nlattr[];
extern u8 real__skb_get_nlattr_nest[];
extern u8 real__get_raw_cpu_id[];
extern u8 realbpf_user_rnd_u32[];
extern u8 real__bpf_call_base[];
#endif

#endif
