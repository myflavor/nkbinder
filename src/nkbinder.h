#define PERF_BUFFER
// #define RING_BUFFER

#define TF_ONE_WAY 0x01


struct binder_transaction_event {
    int from_uid;
    int from_pid;
    int to_pid;
    unsigned int code;
    unsigned int flags;
};
