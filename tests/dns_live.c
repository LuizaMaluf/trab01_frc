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
    dns_rr_t rrs[DNS_MAX_RR];
    mx_record_t mx[DNS_MAX_MX];
    dns_status_t status;
    int count;

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

    /* Fase 10: percorre os registros da resposta e mostra o que encontrou. */
    if (parse_answers(response, (size_t)response_length, rrs, DNS_MAX_RR, &count) != 0) {
        fprintf(stderr, "Resposta truncada ou malformada.\n");
        return 1;
    }
    for (int i = 0; i < count; i++) {
        printf("Answer %d:\nTYPE: %u%s\nCLASS: %u\nTTL: %u\nRDLENGTH: %u\n",
               i + 1, rrs[i].type, rrs[i].type == DNS_TYPE_MX ? " (MX)" : "",
               rrs[i].rrclass, rrs[i].ttl, rrs[i].rdlength);
    }

    /* Fase 11: extrai os registros MX e mostra o resultado final. */
    status = parse_response(response, (size_t)response_length, mx, DNS_MAX_MX, &count);
    switch (status) {
    case DNS_OK:
        for (int i = 0; i < count; i++) {
            printf("Preference: %u\nExchange: %s\n", mx[i].preference, mx[i].exchange);
        }
        break;
    case DNS_ERR_NXDOMAIN:
        printf("Status: dominio nao existe (NXDOMAIN)\n");
        break;
    case DNS_ERR_NO_MX:
        printf("Status: dominio existe, mas nao possui entrada MX\n");
        break;
    default:
        printf("Status: resposta invalida ou erro do servidor\n");
        break;
    }
    return 0;
}
