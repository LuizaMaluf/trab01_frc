#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dns.h"

enum scenario {
    RESPOND_ON_SECOND,
    NEVER_RESPOND,
    WRONG_ID_THEN_CORRECT
};

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int run_scenario(enum scenario scenario, const char *description)
{
    static const uint8_t answer[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    struct sockaddr_in local = {0};
    struct sockaddr_in client = {0};
    struct timeval server_timeout = { .tv_sec = DNS_TIMEOUT_SEC + 2, .tv_usec = 0 };
    struct pollfd pending = { .events = POLLIN };
    socklen_t local_len = sizeof(local);
    uint8_t query[DNS_MAX_MSG];
    uint8_t received_query[DNS_MAX_MSG];
    uint8_t wrong_answer[sizeof(answer)];
    int expected_requests = scenario == NEVER_RESPOND ? DNS_MAX_TRIES :
                            scenario == RESPOND_ON_SECOND ? 2 : 1;
    int query_len = build_query(query, sizeof(query), "unb.br", 0x1234);
    int server;
    int status;
    int ok = 1;
    int64_t started;
    pid_t child;

    if (query_len < 0) {
        fprintf(stderr, "FALHOU: montagem da consulta de teste\n");
        return 1;
    }

    server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server < 0) {
        perror("socket do teste");
        return 1;
    }
    local.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) != 1) {
        close(server);
        return 1;
    }
    local.sin_port = 0;
    if (bind(server, (const struct sockaddr *)&local, sizeof(local)) < 0 ||
        getsockname(server, (struct sockaddr *)&local, &local_len) < 0 ||
        setsockopt(server, SOL_SOCKET, SO_RCVTIMEO,
                   &server_timeout, sizeof(server_timeout)) < 0) {
        perror("preparacao do servidor UDP de teste");
        close(server);
        return 1;
    }

    started = monotonic_ms();
    if (started < 0) {
        close(server);
        return 1;
    }
    child = fork();
    if (child < 0) {
        perror("preparacao do cliente de teste");
        close(server);
        return 1;
    }

    if (child == 0) {
        uint8_t response[DNS_MAX_MSG];
        int result;

        close(server);
        result = send_and_receive_to("127.0.0.1", ntohs(local.sin_port),
                                     query, (size_t)query_len,
                                     response, sizeof(response), 0x1234);
        if (scenario == NEVER_RESPOND ? result != -1 :
            result != (int)sizeof(answer) ||
            memcmp(response, answer, sizeof(answer)) != 0) {
            fprintf(stderr, "FALHOU: resultado do cliente em %s\n", description);
            _exit(1);
        }
        _exit(0);
    }

    for (int i = 0; i < expected_requests; i++) {
        socklen_t client_len = sizeof(client);
        ssize_t received = recvfrom(server, received_query, sizeof(received_query),
                                    0, (struct sockaddr *)&client, &client_len);
        if (received != query_len ||
            (received == query_len &&
             memcmp(received_query, query, (size_t)query_len) != 0)) {
            fprintf(stderr, "FALHOU: consulta %d em %s\n", i + 1, description);
            ok = 0;
            break;
        }

        if (i == expected_requests - 1 && scenario != NEVER_RESPOND) {
            if (scenario == WRONG_ID_THEN_CORRECT) {
                memcpy(wrong_answer, answer, sizeof(answer));
                wrong_answer[1]++;
                if (sendto(server, wrong_answer, sizeof(wrong_answer), 0,
                           (const struct sockaddr *)&client, client_len) !=
                    (ssize_t)sizeof(wrong_answer)) {
                    ok = 0;
                }
            }
            if (sendto(server, answer, sizeof(answer), 0,
                       (const struct sockaddr *)&client, client_len) !=
                (ssize_t)sizeof(answer)) {
                ok = 0;
            }
        }
    }

    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ok = 0;
    }

    pending.fd = server;
    if (poll(&pending, 1, 0) != 0) {
        fprintf(stderr, "FALHOU: envio adicional em %s\n", description);
        ok = 0;
    }
    close(server);

    if (scenario == RESPOND_ON_SECOND &&
        monotonic_ms() - started < DNS_TIMEOUT_SEC * 1000 - 100) {
        fprintf(stderr, "FALHOU: retransmissao antes do timeout\n");
        ok = 0;
    }
    if (scenario == NEVER_RESPOND &&
        monotonic_ms() - started < DNS_MAX_TRIES * DNS_TIMEOUT_SEC * 1000 - 100) {
        fprintf(stderr, "FALHOU: espera menor que tres timeouts\n");
        ok = 0;
    }

    if (!ok) {
        return 1;
    }
    printf("PASSOU: %s\n", description);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_scenario(RESPOND_ON_SECOND, "resposta na segunda tentativa");
    failures += run_scenario(NEVER_RESPOND, "tres tentativas sem resposta");
    failures += run_scenario(WRONG_ID_THEN_CORRECT, "ID incorreto ignorado");

    if (failures != 0) {
        return 1;
    }
    printf("Todos os testes da Fase 6 passaram.\n");
    return 0;
}
