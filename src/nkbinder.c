#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nkbinder.h"

#define SOCKET_NAME "nkbinder"
#define MESSAGE_LENGTH 128
#define NET_BPF_OBJ "nkbinder_network.bpf.o"

static volatile int running = 1;
void sig_handler(int sig) { running = 0; }

int setup_socket_server()
{
    int server_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (server_fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    addr.sun_path[0] = 0;
    strncpy(addr.sun_path + 1, SOCKET_NAME, sizeof(addr.sun_path) - 2);
    int len = 1 + strlen(SOCKET_NAME) + offsetof(struct sockaddr_un, sun_path);

    if (bind(server_fd, (struct sockaddr *)&addr, len) < 0)
    {
        close(server_fd);
        return -1;
    }
    listen(server_fd, 5);
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK);
    return server_fd;
}

/* Increase rlimit for BPF operations */
static void bump_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &r);
}

/* Create raw socket for BPF socket filter attachment */
static int create_raw_socket(const char *ifname)
{
    int sock;
    struct sockaddr_ll sll;
    int ret;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "[-] Failed to create raw socket: %s\n", strerror(errno));
        return -1;
    }

    if (ifname) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

        ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
        if (ret < 0) {
            fprintf(stderr, "[-] Failed to get interface flags: %s\n", strerror(errno));
            close(sock);
            return -1;
        }

        ret = ioctl(sock, SIOCGIFINDEX, &ifr);
        if (ret < 0) {
            fprintf(stderr, "[-] Failed to get interface index: %s\n", strerror(errno));
            close(sock);
            return -1;
        }

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        ret = bind(sock, (struct sockaddr *)&sll, sizeof(sll));
        if (ret < 0) {
            fprintf(stderr, "[-] Failed to bind raw socket: %s\n", strerror(errno));
            close(sock);
            return -1;
        }

        printf("[+] Bound to interface: %s (index %d)\n", ifname, ifr.ifr_ifindex);
    }

    return sock;
}

/* Attach BPF program to socket via SO_ATTACH_BPF */
static int attach_bpf_to_socket(int sock_fd, int prog_fd)
{
    int ret = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (ret < 0) {
        fprintf(stderr, "[-] SO_ATTACH_BPF failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    int *client_fd_ptr = (int *)ctx;
    struct nkbinder_event *e = (struct nkbinder_event *)data;
    char buffer[MESSAGE_LENGTH];
    int n = 0;

    if (e->type == TYPE_BINDER)
    {
        if (e->binder.flags & TF_ONE_WAY)
            return 0;

        n = snprintf(buffer, sizeof(buffer),
                     "type=syncBinder from_uid=%d from_pid=%d to_pid=%d code=%u",
                     e->binder.from_uid, e->binder.from_pid, e->binder.to_pid, e->binder.code);

        printf("[DEBUG] BINDER: from_pid:%d -> to_pid:%d\n",
               e->binder.from_pid, e->binder.to_pid);
    }
    else if (e->type == TYPE_SIGNAL)
    {
        n = snprintf(buffer, sizeof(buffer),
                     "type=signal from_pid=%d to_pid=%d signal=%d",
                     e->signal.from_pid, e->signal.to_pid, e->signal.signal);

        printf("[DEBUG] SIGNAL: %d sent sig %d to %d\n",
               e->signal.from_pid, e->signal.signal, e->signal.to_pid);
    }
    else if (e->type == TYPE_NETWORK)
    {
        const char *family_str = (e->network.family == NF_FAMILY_IPV6) ? "ipv6" : "ipv4";
        n = snprintf(buffer, sizeof(buffer),
                     "type=Network uid=%d family=%s data_len=%d",
                     e->network.uid, family_str, e->network.data_len);

        printf("[DEBUG] NETWORK: uid=%d family=%s data_len=%d\n",
               e->network.uid, family_str, e->network.data_len);
    }
    else
    {
        return 0;
    }

    if (n > 0 && n < MESSAGE_LENGTH - 1)
    {
        memset(buffer + n, ' ', MESSAGE_LENGTH - n - 1);
        buffer[MESSAGE_LENGTH - 1] = '\n';
    }

    if (*client_fd_ptr != -1)
    {
        if (send(*client_fd_ptr, buffer, MESSAGE_LENGTH, MSG_NOSIGNAL) < 0)
        {
            close(*client_fd_ptr);
            *client_fd_ptr = -1;
        }
    }
    return 0;
}

void handle_perf_event(void *ctx, int cpu, void *data, __u32 size)
{
    handle_event(ctx, data, size);
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj_binder = NULL;
    struct bpf_object *obj_network = NULL;
    struct ring_buffer *rb_binder = NULL;
    struct ring_buffer *rb_network = NULL;
    struct perf_buffer *pb_binder = NULL;
    struct perf_buffer *pb_network = NULL;
    struct bpf_program *prog_binder = NULL;
    struct bpf_program *prog_signal = NULL;
    struct bpf_program *prog_network = NULL;
    struct bpf_link *link_binder = NULL;
    struct bpf_link *link_signal = NULL;
    int server_fd = -1;
    int client_fd = -1;
    int map_fd = -1;
    int prog_fd_network = -1;
    int raw_sock = -1;
    const char *ifname = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    bump_rlimit();

    /* Parse optional interface name */
    if (argc > 1)
        ifname = argv[1];

    server_fd = setup_socket_server();
    if (server_fd < 0)
    {
        fprintf(stderr, "[-] Failed to setup socket server\n");
        return 1;
    }

    printf("[+] Socket server started\n");

    /*
     * Load and attach Binder/Signal BPF programs
     */
    obj_binder = bpf_object__open_file("nkbinder.bpf.o", NULL);
    if (libbpf_get_error(obj_binder))
    {
        fprintf(stderr, "[-] Error opening binder BPF object\n");
        goto cleanup;
    }

    if (bpf_object__load(obj_binder))
    {
        fprintf(stderr, "[-] Error loading binder BPF object\n");
        goto cleanup;
    }

    prog_binder = bpf_object__find_program_by_name(obj_binder, "tp_binder_transaction");
    prog_signal = bpf_object__find_program_by_name(obj_binder, "handle_signal_gen");

    if (prog_binder)
    {
        link_binder = bpf_program__attach(prog_binder);
        if (libbpf_get_error(link_binder))
        {
            fprintf(stderr, "[-] Failed to attach Binder tracepoint\n");
            link_binder = NULL;
        }
        else
        {
            printf("[+] Attached Binder tracepoint\n");
        }
    }

    if (prog_signal)
    {
        link_signal = bpf_program__attach(prog_signal);
        if (libbpf_get_error(link_signal))
        {
            fprintf(stderr, "[-] Failed to attach Signal tracepoint\n");
            link_signal = NULL;
        }
        else
        {
            printf("[+] Attached Signal tracepoint\n");
        }
    }

    if (!link_binder && !link_signal)
    {
        fprintf(stderr, "[-] Warning: No binder/signal programs attached\n");
    }

    /*
     * Load Network BPF program (non-CO-RE socket filter)
     */
    obj_network = bpf_object__open_file(NET_BPF_OBJ, NULL);
    if (libbpf_get_error(obj_network))
    {
        fprintf(stderr, "[-] Warning: Cannot open %s: %s\n", NET_BPF_OBJ, strerror(errno));
        fprintf(stderr, "    Network monitoring will be disabled\n");
        obj_network = NULL;
    }
    else
    {
        if (bpf_object__load(obj_network))
        {
            fprintf(stderr, "[-] Error loading network BPF object: %s\n", strerror(errno));
            bpf_object__close(obj_network);
            obj_network = NULL;
        }
        else
        {
            printf("[+] Network BPF object loaded\n");

            /* Find socket filter program */
            prog_network = bpf_object__find_program_by_name(obj_network, "nkbinder_sock_filter");
            if (!prog_network) {
                prog_network = bpf_object__next_program(obj_network, NULL);
            }

            if (prog_network)
            {
                prog_fd_network = bpf_program__fd(prog_network);
                printf("[+] Found network socket filter program (fd=%d)\n", prog_fd_network);
            }
        }
    }

    /*
     * Attach network BPF program via raw socket + SO_ATTACH_BPF
     */
    if (prog_fd_network > 0)
    {
        raw_sock = create_raw_socket(ifname);
        if (raw_sock >= 0)
        {
            if (attach_bpf_to_socket(raw_sock, prog_fd_network) == 0)
            {
                printf("[+] Network BPF socket filter attached\n");
            }
            else
            {
                fprintf(stderr, "[-] Failed to attach socket filter: %s\n", strerror(errno));
                fprintf(stderr, "    Hint: Need CAP_NET_RAW capability or root\n");
            }
        }
    }

    /*
     * Set up event buffers for network program
     */
#ifdef RING_BUFFER
    if (obj_network)
    {
        map_fd = bpf_object__find_map_fd_by_name(obj_network, "network_rb");
        if (map_fd > 0)
        {
            rb_network = ring_buffer__new(map_fd, handle_event, &client_fd, NULL);
            if (!rb_network)
            {
                fprintf(stderr, "[-] Failed to create ring buffer for network\n");
            }
            else
            {
                printf("[+] Network events via Ring Buffer\n");
            }
        }
    }
#endif
#ifdef PERF_BUFFER
    if (obj_network)
    {
        map_fd = bpf_object__find_map_fd_by_name(obj_network, "network_rb");
        if (map_fd > 0)
        {
            pb_network = perf_buffer__new(map_fd, 8, handle_perf_event, NULL, &client_fd, NULL);
            if (!pb_network)
            {
                fprintf(stderr, "[-] Failed to create perf buffer for network\n");
            }
            else
            {
                printf("[+] Network events via Perf Buffer\n");
            }
        }
    }
#endif

    /*
     * Set up event buffers for binder program
     */
#ifdef RING_BUFFER
    if (obj_binder)
    {
        map_fd = bpf_object__find_map_fd_by_name(obj_binder, "rb");
        if (map_fd > 0)
        {
            rb_binder = ring_buffer__new(map_fd, handle_event, &client_fd, NULL);
            if (!rb_binder)
            {
                fprintf(stderr, "[-] Failed to create ring buffer for binder\n");
            }
            else
            {
                printf("[+] Binder events via Ring Buffer\n");
            }
        }
    }
#endif
#ifdef PERF_BUFFER
    if (obj_binder)
    {
        map_fd = bpf_object__find_map_fd_by_name(obj_binder, "pb");
        if (map_fd > 0)
        {
            pb_binder = perf_buffer__new(map_fd, 8, handle_perf_event, NULL, &client_fd, NULL);
            if (!pb_binder)
            {
                fprintf(stderr, "[-] Failed to create perf buffer for binder\n");
            }
            else
            {
                printf("[+] Binder events via Perf Buffer\n");
            }
        }
    }
#endif

    if (!rb_binder && !pb_binder && !rb_network && !pb_network)
    {
        fprintf(stderr, "[-] Warning: No event buffers available\n");
    }

    printf("[+] nkbinder started, waiting for events...\n");

    /* Main event loop */
    while (running)
    {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (new_fd != -1)
        {
            if (client_fd != -1)
                close(client_fd);
            client_fd = new_fd;
            printf("[+] Client connected\n");
        }

#ifdef RING_BUFFER
        if (rb_binder)
            ring_buffer__poll(rb_binder, 100);
        if (rb_network)
            ring_buffer__poll(rb_network, 100);
#endif
#ifdef PERF_BUFFER
        if (pb_binder)
            perf_buffer__poll(pb_binder, 100);
        if (pb_network)
            perf_buffer__poll(pb_network, 100);
#endif

        usleep(1000);
    }

cleanup:
    printf("[+] Shutting down...\n");
    if (client_fd != -1)
        close(client_fd);
    if (server_fd != -1)
        close(server_fd);
    if (raw_sock >= 0)
        close(raw_sock);
    if (rb_binder)
        ring_buffer__free(rb_binder);
    if (rb_network)
        ring_buffer__free(rb_network);
    if (pb_binder)
        perf_buffer__free(pb_binder);
    if (pb_network)
        perf_buffer__free(pb_network);
    if (link_binder)
        bpf_link__destroy(link_binder);
    if (link_signal)
        bpf_link__destroy(link_signal);
    if (obj_binder)
        bpf_object__close(obj_binder);
    if (obj_network)
        bpf_object__close(obj_network);

    return 0;
}
