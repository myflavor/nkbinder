#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include "nkbinder.h"

#ifdef PERF_BUFFER
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} pb SEC(".maps");

#endif

#ifdef RING_BUFFER
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
#endif

static __always_inline void send_event(void *ctx, struct nkbinder_event *ev)
{
#ifdef PERF_BUFFER
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
#endif

#ifdef RING_BUFFER
    struct nkbinder_event *data = bpf_ringbuf_reserve(&rb, sizeof(*ev), 0);
    if (data)
    {
        __builtin_memcpy(data, ev, sizeof(*ev));
        bpf_ringbuf_submit(data, 0);
    }
#endif
}

struct binder_transaction_args
{
    unsigned long long ignore;
    int debug_id;
    int target_node;
    int to_proc;
    unsigned int code;
    unsigned int flags;
};

SEC("tracepoint/binder/binder_transaction")
int tp_binder_transaction(struct binder_transaction_args *args)
{
    struct nkbinder_event ev = {};

    ev.type = TYPE_BINDER;
    ev.binder.from_uid = (int)bpf_get_current_uid_gid();
    ev.binder.from_pid = (int)(bpf_get_current_pid_tgid() >> 32);
    ev.binder.to_pid = args->to_proc;
    ev.binder.code = args->code;
    ev.binder.flags = args->flags;

    send_event(args, &ev);
    return 0;
}

struct tp_signal_generate_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int sig;
    int errno;
    int code;
    char comm[16];
    int pid;
    int group;
    int result;
};

SEC("tracepoint/signal/signal_generate")
int handle_signal_gen(struct tp_signal_generate_ctx *ctx)
{
    struct nkbinder_event ev = {};
    ev.type = TYPE_SIGNAL;
    ev.signal.from_pid = (int)(bpf_get_current_pid_tgid() >> 32);
    ev.signal.to_pid = ctx->pid;
    ev.signal.signal = ctx->sig;

    send_event(ctx, &ev);
    return 0;
}

char _license[] SEC("license") = "GPL";