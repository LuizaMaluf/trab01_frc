#include "dns.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int send_and_receive_to(const char *server_ip, uint16_t port,
                        const uint8_t *query, size_t qlen,
                        uint8_t *resp, size_t resplen, uint16_t id)
{
    struct sockaddr_in destination = {0};
    struct sockaddr_in source = {0};
    struct timeval timeout = { .tv_sec = DNS_TIMEOUT_SEC, .tv_usec = 0 };
    socklen_t source_len = sizeof(source);
    ssize_t sent;
    ssize_t received;
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

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(fd);
        return -1;
    }

    sent = sendto(fd, query, qlen, 0,
                  (const struct sockaddr *)&destination, sizeof(destination));
    if (sent != (ssize_t)qlen) {
        close(fd);
        return -1;
    }

    received = recvfrom(fd, resp, resplen, 0,
                        (struct sockaddr *)&source, &source_len);
    close(fd);

    if (received < 2 || source.sin_family != AF_INET ||
        source.sin_port != destination.sin_port ||
        source.sin_addr.s_addr != destination.sin_addr.s_addr ||
        resp[0] != (uint8_t)(id >> 8) || resp[1] != (uint8_t)id) {
        return -1;
    }

    return (int)received;
}

int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id)
{
    return send_and_receive_to(server_ip, DNS_PORT, query, qlen,
                               resp, resplen, id);
}
