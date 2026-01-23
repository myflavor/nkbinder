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
    struct binder_transaction_event *e = (struct binder_transaction_event *)data;
    if (e->flags & TF_ONE_WAY)
        return 0;

    char buffer[MESSAGE_LENGTH];
    int n = snprintf(buffer, sizeof(buffer), "type=syncBinder from_uid=%d from_pid=%d to_pid=%d code=%u",
                     e->from_uid, e->from_pid, e->to_pid, e->code);

    if (n < MESSAGE_LENGTH - 1)
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
    printf("[DEBUG] from_pid:%d -> to_pid:%d\n", e->from_pid, e->to_pid);
    return 0;
}

void handle_perf_event(void *ctx, int cpu, void *data, __u32 size)
{
    handle_event(ctx, data, size);
}

int main()
{
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    struct perf_buffer *pb = NULL;
    struct bpf_program *prog = NULL;
    int server_fd = -1;
    int client_fd = -1;
    int map_fd;

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

    prog = bpf_object__find_program_by_name(obj, "tp_binder_transaction");
    if (!prog)
    {
        fprintf(stderr, "[-] Program not found\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "[-] Failed to attach\n");
        goto cleanup;
    }

// 4. 初始化缓冲区
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
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    return 0;
}