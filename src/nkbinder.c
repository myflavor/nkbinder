#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nkbinder.h"

#define SOCKET_NAME "nkbinder"
#define MESSAGE_LENGTH 128

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

int main()
{
    struct bpf_object *obj = NULL;
    struct ring_buffer *rb = NULL;
    struct perf_buffer *pb = NULL;
    struct bpf_program *prog_binder = NULL;
    struct bpf_program *prog_signal = NULL;
    struct bpf_link *link_binder = NULL;
    struct bpf_link *link_signal = NULL;
    int server_fd = -1;
    int client_fd = -1;
    int map_fd = -1;

    signal(SIGINT, sig_handler);

    server_fd = setup_socket_server();
    if (server_fd < 0)
    {
        fprintf(stderr, "[-] Failed to setup socket server\n");
        return 1;
    }

    obj = bpf_object__open_file("nkbinder.bpf.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "[-] Error opening BPF object\n");
        goto cleanup;
    }

    if (bpf_object__load(obj))
    {
        fprintf(stderr, "[-] Error loading BPF object\n");
        goto cleanup;
    }

    prog_binder = bpf_object__find_program_by_name(obj, "tp_binder_transaction");
    prog_signal = bpf_object__find_program_by_name(obj, "handle_signal_gen");

    if (prog_binder)
    {
        link_binder = bpf_program__attach(prog_binder);
        if (libbpf_get_error(link_binder))
        {
            fprintf(stderr, "[-] Failed to attach Binder: %s\n", strerror(errno));
            link_binder = NULL;
        }
        else
        {
            printf("[+] Attached Binder Tracepoint\n");
        }
    }

    if (prog_signal)
    {
        link_signal = bpf_program__attach(prog_signal);
        if (libbpf_get_error(link_signal))
        {
            fprintf(stderr, "[-] Failed to attach Signal: %s\n", strerror(errno));
            link_signal = NULL;
        }
        else
        {
            printf("[+] Attached Signal Tracepoint\n");
        }
    }

    if (!link_binder && !link_signal)
    {
        fprintf(stderr, "[-] Critical: No programs attached. Exiting.\n");
        goto cleanup;
    }

#ifdef RING_BUFFER
    map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    rb = ring_buffer__new(map_fd, handle_event, &client_fd, NULL);
    if (!rb)
    {
        fprintf(stderr, "[-] Failed to create ring buffer\n");
        goto cleanup;
    }
    printf("[+] Monitoring via Ring Buffer\n");
#endif
#ifdef PERF_BUFFER
    map_fd = bpf_object__find_map_fd_by_name(obj, "pb");
    pb = perf_buffer__new(map_fd, 8, handle_perf_event, NULL, &client_fd, NULL);
    if (libbpf_get_error(pb))
    {
        fprintf(stderr, "[-] Failed to create perf buffer\n");
        goto cleanup;
    }
    printf("[!] Using Perf Buffer\n");
#endif

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
        ring_buffer__poll(rb, 100);
#endif
#ifdef PERF_BUFFER
        perf_buffer__poll(pb, 100);
#endif
    }

cleanup:
    if (client_fd != -1)
        close(client_fd);
    if (server_fd != -1)
        close(server_fd);
    if (rb)
        ring_buffer__free(rb);
    if (pb)
        perf_buffer__free(pb);
    if (link_binder)
        bpf_link__destroy(link_binder);
    if (link_signal)
        bpf_link__destroy(link_signal);
    if (obj)
        bpf_object__close(obj);
    return 0;
}