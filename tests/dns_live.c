#include <stdint.h>
#include <stdio.h>

#include "dns.h"

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        printf("%02x%s", bytes[i], (i + 1) % 16 == 0 || i + 1 == length ? "\n" : " ");
    }
}

int main(int argc, char *argv[])
{
    const uint16_t id = 0x1234; /* ID fixo para facilitar a leitura da demonstracao. */
    uint8_t query[DNS_MAX_MSG];
    uint8_t response[DNS_MAX_MSG];
    int query_length;
    int response_length;

    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dominio> <ip_servidor_dns>\n", argv[0]);
        return 1;
    }

    query_length = build_query(query, sizeof(query), argv[1], id);
    if (query_length < 0) {
        fprintf(stderr, "Dominio invalido ou consulta grande demais.\n");
        return 1;
    }

    printf("Consulta MX para %s (%d bytes):\n", argv[1], query_length);
    print_hex(query, (size_t)query_length);
    fflush(stdout);

    response_length = send_and_receive(argv[2], query, (size_t)query_length,
                                       response, sizeof(response), id);
    if (response_length < 0) {
        fprintf(stderr, "Nenhuma resposta correspondente de %s apos ate %d tentativas.\n",
                argv[2], DNS_MAX_TRIES);
        return 1;
    }

    printf("Resposta recebida de %s (%d bytes):\n", argv[2], response_length);
    print_hex(response, (size_t)response_length);
    return 0;
}
