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

/* Resultados de wait_for_response quando nao ha resposta valida (um retorno
 * positivo e o tamanho da resposta). */
#define WAIT_TIMEOUT 0
#define WAIT_ERROR   (-1)

/* A resposta e valida se veio do servidor consultado (IP e porta) e repete o
 * Transaction ID da consulta; qualquer outro datagrama e ignorado. */
static int is_expected_reply(const struct sockaddr_in *source,
                             const struct sockaddr_in *server,
                             const uint8_t *resp, ssize_t received, uint16_t id)
{
    return received >= 2 &&
           source->sin_family == AF_INET &&
           source->sin_port == server->sin_port &&
           source->sin_addr.s_addr == server->sin_addr.s_addr &&
           resp[0] == (uint8_t)(id >> 8) && resp[1] == (uint8_t)id;
}

/* Espera ate deadline (relogio monotonico, em ms) pela resposta do servidor.
 * Retorna o tamanho da resposta, WAIT_TIMEOUT ou WAIT_ERROR. */
static int wait_for_response(int fd, const struct sockaddr_in *server, uint16_t id,
                             uint8_t *resp, size_t resplen, int64_t deadline)
{
    struct pollfd pending = { .fd = fd, .events = POLLIN };

    for (;;) {
        struct sockaddr_in source = {0};
        socklen_t source_len = sizeof(source);
        int64_t now = monotonic_ms();
        int64_t remaining;
        ssize_t received;
        int ready;

        if (now < 0) {
            return WAIT_ERROR;
        }
        remaining = deadline - now;
        if (remaining <= 0) {
            return WAIT_TIMEOUT;
        }

        ready = poll(&pending, 1, (int)remaining);
        if (ready == 0) {
            return WAIT_TIMEOUT;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return WAIT_ERROR;
        }
        if ((pending.revents & POLLIN) == 0) {
            return WAIT_ERROR;
        }

        received = recvfrom(fd, resp, resplen, 0,
                            (struct sockaddr *)&source, &source_len);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return WAIT_ERROR;
        }

        if (is_expected_reply(&source, server, resp, received, id)) {
            return (int)received;
        }
    }
}

int send_and_receive_to(const char *server_ip, uint16_t port,
                        const uint8_t *query, size_t qlen,
                        uint8_t *resp, size_t resplen, uint16_t id)
{
    struct sockaddr_in destination = {0};
    int result = -1;
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

    /* Ate DNS_MAX_TRIES envios, cada um com DNS_TIMEOUT_SEC de espera. Um erro
     * (que nao seja timeout) encerra as tentativas. */
    for (int attempt = 0; attempt < DNS_MAX_TRIES; attempt++) {
        int64_t deadline = monotonic_ms();
        int got;

        if (sendto(fd, query, qlen, 0, (const struct sockaddr *)&destination,
                   sizeof(destination)) != (ssize_t)qlen || deadline < 0) {
            break;
        }

        got = wait_for_response(fd, &destination, id, resp, resplen,
                                deadline + DNS_TIMEOUT_SEC * 1000);
        if (got > 0) {
            result = got;
            break;
        }
        if (got == WAIT_ERROR) {
            break;
        }
    }

    close(fd);
    return result;
}

int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id)
{
    return send_and_receive_to(server_ip, DNS_PORT, query, qlen,
                               resp, resplen, id);
}
