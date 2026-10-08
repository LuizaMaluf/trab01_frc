#define _POSIX_C_SOURCE 200809L

#include "dns.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Transaction ID de 16 bits aleatorio. Usa o gerador do sistema operacional
 * e, se ele nao estiver disponivel, cai para rand() semeado com hora e PID. */
static uint16_t random_id(void)
{
    uint8_t bytes[2];
    FILE *source = fopen("/dev/urandom", "rb");

    if (source != NULL) {
        size_t got = fread(bytes, 1, sizeof(bytes), source);

        fclose(source);
        if (got == sizeof(bytes)) {
            return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
        }
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    return (uint16_t)(rand() ^ (rand() << 8));
}

int run_client(FILE *out, const char *domain, const char *server_ip, uint16_t port)
{
    uint8_t query[DNS_MAX_MSG];
    uint8_t response[DNS_MAX_MSG];
    mx_record_t mx[DNS_MAX_MX];
    uint16_t id = random_id();
    int count = 0;
    int query_len;
    int response_len;

    query_len = build_query(query, sizeof(query), domain, id);
    if (query_len < 0) {
        fprintf(out, "Dominio %s invalido\n", domain);
        return 1;
    }

    /* Sem resposta valida do servidor (timeout, IP invalido, falha de socket). */
    response_len = send_and_receive_to(server_ip, port, query, (size_t)query_len,
                                       response, sizeof(response), id);
    if (response_len < 0) {
        fprintf(out, "Nao foi possível coletar entrada MX para %s\n", domain);
        return 1;
    }

    switch (parse_response(response, (size_t)response_len, mx, DNS_MAX_MX, &count)) {
    case DNS_OK:
        for (int i = 0; i < count; i++) {
            fprintf(out, "%s <> %s\n", domain, mx[i].exchange);
        }
        return 0;
    case DNS_ERR_NXDOMAIN:
        fprintf(out, "Dominio %s nao encontrado\n", domain);
        return 1;
    case DNS_ERR_NO_MX:
        fprintf(out, "Dominio %s nao possui entrada MX\n", domain);
        return 1;
    default:
        /* Resposta truncada ou invalida, ou erro do servidor (SERVFAIL, REFUSED...):
         * a consulta nao pode ser concluida. */
        fprintf(out, "Nao foi possível coletar entrada MX para %s\n", domain);
        return 1;
    }
}
