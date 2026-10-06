#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

static int failures = 0;

static void check_valid(const char *domain, const uint8_t *expected,
                        size_t expected_len)
{
    uint8_t actual[DNS_MAX_WIRE_NAME];
    int result = encode_dns_name(domain, actual, sizeof(actual));

    if (result != (int)expected_len ||
        memcmp(actual, expected, expected_len) != 0) {
        fprintf(stderr, "FALHOU: codificacao de %s\n", domain);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", domain);
}

static void check_invalid(const char *description, const char *domain,
                          size_t buffer_size)
{
    uint8_t buffer[DNS_MAX_WIRE_NAME];

    if (encode_dns_name(domain, buffer, buffer_size) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

int main(void)
{
    static const uint8_t unb_br[] = {
        3, 'u', 'n', 'b', 2, 'b', 'r', 0
    };
    static const uint8_t google_com[] = {
        6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0
    };
    static const uint8_t mail_google_com[] = {
        4, 'm', 'a', 'i', 'l',
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm', 0
    };
    char long_label[65];

    memset(long_label, 'a', 64);
    long_label[64] = '\0';

    check_valid("unb.br", unb_br, sizeof(unb_br));
    check_valid("google.com", google_com, sizeof(google_com));
    check_valid("mail.google.com", mail_google_com, sizeof(mail_google_com));

    check_invalid("dominio vazio", "", DNS_MAX_WIRE_NAME);
    check_invalid("rotulo vazio no meio", "unb..br", DNS_MAX_WIRE_NAME);
    check_invalid("ponto no inicio", ".unb.br", DNS_MAX_WIRE_NAME);
    check_invalid("ponto no final", "unb.br.", DNS_MAX_WIRE_NAME);
    check_invalid("rotulo com mais de 63 caracteres", long_label,
                  DNS_MAX_WIRE_NAME);
    check_invalid("buffer pequeno", "unb.br", sizeof(unb_br) - 1);

    if (failures != 0) {
        fprintf(stderr, "%d teste(s) da Fase 2 falharam.\n", failures);
        return 1;
    }

    printf("Todos os testes da Fase 2 passaram.\n");
    return 0;
}
