#define PERF_BUFFER
// #define RING_BUFFER

#define TF_ONE_WAY 0x01

#define TYPE_BINDER 1
#define TYPE_SIGNAL 2
#define TYPE_NETWORK 3

#define NF_FAMILY_IPV4 4
#define NF_FAMILY_IPV6 6

#define MIN_USERAPP_UID 10000

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

struct network_event
{
    int uid;
    int family;
    int data_len;
};

struct nkbinder_event
{

    int type;

    union
    {
        struct binder_transaction_event binder;
        struct signal_event signal;
        struct network_event network;
    };
};
