#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dns.h"

int main(void)
{
    static const uint8_t answer[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    struct sockaddr_in local = {0};
    struct sockaddr_in client = {0};
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    socklen_t local_len = sizeof(local);
    socklen_t client_len = sizeof(client);
    uint8_t query[DNS_MAX_MSG];
    uint8_t received_query[DNS_MAX_MSG];
    int query_len;
    int server;
    int status;
    int ok = 1;
    ssize_t received;
    pid_t child;

    query_len = build_query(query, sizeof(query), "unb.br", 0x1234);
    if (query_len != 24) {
        fprintf(stderr, "FALHOU: consulta DNS de teste\n");
        return 1;
    }

    if (send_and_receive("IP-invalido", query, (size_t)query_len,
                         received_query, sizeof(received_query), 0x1234) != -1) {
        fprintf(stderr, "FALHOU: IP invalido deveria ser rejeitado\n");
        return 1;
    }

    server = socket(AF_INET, SOCK_DGRAM, 0);
    if (server < 0) {
        perror("socket do teste");
        return 1;
    }

    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = 0; /* O sistema escolhe uma porta local disponivel. */
    if (bind(server, (const struct sockaddr *)&local, sizeof(local)) < 0 ||
        getsockname(server, (struct sockaddr *)&local, &local_len) < 0 ||
        setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("preparacao do servidor UDP de teste");
        close(server);
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork do teste");
        close(server);
        return 1;
    }

    if (child == 0) {
        uint8_t response[DNS_MAX_MSG];
        int response_len;

        close(server);
        response_len = send_and_receive_to("127.0.0.1", ntohs(local.sin_port),
                                           query, (size_t)query_len,
                                           response, sizeof(response), 0x1234);
        if (response_len != (int)sizeof(answer) ||
            memcmp(response, answer, sizeof(answer)) != 0) {
            fprintf(stderr, "FALHOU: recebimento da resposta UDP\n");
            _exit(1);
        }

        _exit(0);
    }

    received = recvfrom(server, received_query, sizeof(received_query), 0,
                        (struct sockaddr *)&client, &client_len);
    if (received != query_len ||
        (received == query_len &&
         memcmp(received_query, query, (size_t)query_len) != 0)) {
        fprintf(stderr, "FALHOU: envio da consulta UDP\n");
        ok = 0;
    }

    if (received >= 0 &&
        sendto(server, answer, sizeof(answer), 0,
               (const struct sockaddr *)&client, client_len) != (ssize_t)sizeof(answer)) {
        fprintf(stderr, "FALHOU: resposta do servidor UDP de teste\n");
        ok = 0;
    }

    close(server);
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ok = 0;
    }

    if (!ok) {
        return 1;
    }

    printf("PASSOU: consulta UDP enviada e resposta recebida em localhost\n");
    printf("Todos os testes da Fase 5 passaram.\n");
    return 0;
}
