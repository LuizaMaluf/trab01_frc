#define _POSIX_C_SOURCE 200809L

#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return -1;
    }

    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int send_and_receive_to(const char *server_ip, uint16_t port,
                        const uint8_t *query, size_t qlen,
                        uint8_t *resp, size_t resplen, uint16_t id)
{
    struct sockaddr_in destination = {0};
    struct sockaddr_in source = {0};
    struct pollfd pending = { .events = POLLIN };
    socklen_t source_len;
    ssize_t sent;
    ssize_t received;
    int64_t deadline;
    int64_t remaining;
    int fd;

    if (server_ip == NULL || query == NULL || resp == NULL || port == 0 ||
        qlen == 0 || qlen > DNS_MAX_MSG || resplen < 2) {
        return -1;
    }

    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &destination.sin_addr) != 1) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    pending.fd = fd;
    for (int attempt = 0; attempt < DNS_MAX_TRIES; attempt++) {
        sent = sendto(fd, query, qlen, 0,
                      (const struct sockaddr *)&destination, sizeof(destination));
        if (sent != (ssize_t)qlen) {
            close(fd);
            return -1;
        }

        deadline = monotonic_ms();
        if (deadline < 0) {
            close(fd);
            return -1;
        }
        deadline += DNS_TIMEOUT_SEC * 1000;

        for (;;) {
            int64_t now = monotonic_ms();
            if (now < 0) {
                close(fd);
                return -1;
            }
            remaining = deadline - now;
            if (remaining <= 0) {
                break;
            }

            int ready = poll(&pending, 1, (int)remaining);
            if (ready == 0) {
                break;
            }
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return -1;
            }
            if ((pending.revents & POLLIN) == 0) {
                close(fd);
                return -1;
            }

            source_len = sizeof(source);
            received = recvfrom(fd, resp, resplen, 0,
                                (struct sockaddr *)&source, &source_len);
            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return -1;
            }

            if (received >= 2 && source.sin_family == AF_INET &&
                source.sin_port == destination.sin_port &&
                source.sin_addr.s_addr == destination.sin_addr.s_addr &&
                resp[0] == (uint8_t)(id >> 8) && resp[1] == (uint8_t)id) {
                close(fd);
                return (int)received;
            }
        }
    }

    close(fd);
    return -1;
}

int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id)
{
    return send_and_receive_to(server_ip, DNS_PORT, query, qlen,
                               resp, resplen, id);
}
