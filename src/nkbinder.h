#define PERF_BUFFER
// #define RING_BUFFER

#define TF_ONE_WAY 0x01

#define TYPE_BINDER 1
#define TYPE_SIGNAL 2

struct binder_transaction_event
{
    int from_uid;
    int from_pid;
    int to_pid;
    unsigned int code;
    unsigned int flags;
};

struct signal_event
{
    int from_pid;
    int to_pid;
    int signal;
};

struct nkbinder_event
{

    int type;

    union
    {
        struct binder_transaction_event binder;
        struct signal_event signal;
    };
};
