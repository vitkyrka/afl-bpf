#!/bin/sh

nm $1 | while read addr type name; do
	case $name in
		jit_get_*|jit_mod|jit_udiv|__skb_get_poff|__bpf_call_base|bpf_load_pointer|__skb_get_pay_offset|__skb_get_nlattr|__skb_get_nlattr_nest|__get_raw_cpu_id|bpf_user_rnd_u32|bpf_call_base)
			echo ${name#__} = 0x$addr\;
			echo real${name} = 0x$addr\;
			;;
	esac
done
