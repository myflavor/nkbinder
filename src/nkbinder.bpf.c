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

struct binder_transaction_args
{
    unsigned long long ignore;
    int debug_id;
    int target_node;
    int to_proc;
    int to_thread;
    int reply;
    unsigned int code;
    unsigned int flags;
};

SEC("tracepoint/binder/binder_transaction")
int tp_binder_transaction(struct binder_transaction_args *args)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    struct binder_transaction_event event = {};
    event.from_uid = uid;
    event.from_pid = pid;
    event.to_pid = args->to_proc;
    event.code = args->code;
    event.flags = args->flags;

    int debug_id = args->debug_id;

#ifdef PERF_BUFFER
    bpf_perf_event_output(args, &pb, BPF_F_CURRENT_CPU, &event, sizeof(event));
#endif

#ifdef RING_BUFFER
    void *data = bpf_ringbuf_reserve(&rb, sizeof(event), 0);
    if (data)
    {
        __builtin_memcpy(data, &event, sizeof(event));
        bpf_ringbuf_submit(data, 0);
    }
#endif

    return 0;
}

char _license[] SEC("license") = "GPL";