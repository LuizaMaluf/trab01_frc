#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

/* Fases 3-4: header DNS + pacote de consulta completo (RFC 1035 4.1). */

static int failures = 0;

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x%s", buf[i], (i + 1 < len) ? " " : "\n");
    }
}

static void check_query(const char *description, const char *domain, uint16_t id,
                        const uint8_t *expected, size_t expected_len)
{
    uint8_t actual[DNS_MAX_MSG];
    int result = build_query(actual, sizeof(actual), domain, id);

    if (result != (int)expected_len ||
        memcmp(actual, expected, expected_len) != 0) {
        fprintf(stderr, "FALHOU: %s (retorno %d, esperado %d)\n",
                description, result, (int)expected_len);
        if (result > 0) {
            fprintf(stderr, "  obtido:   ");
            print_hex(actual, (size_t)result);
        }
        fprintf(stderr, "  esperado: ");
        print_hex(expected, expected_len);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
}

static void check_small_buffer(const char *description, const char *domain,
                               size_t buffer_size)
{
    /* Sentinela de 4 bytes depois do buffer declarado: build_query deve
     * retornar -1 e nunca escrever alem de buffer_size. */
    uint8_t buffer[DNS_MAX_MSG + 4];
    size_t i;

    memset(buffer, 0xAA, sizeof(buffer));

    if (build_query(buffer, buffer_size, domain, 0x1234) != -1) {
        fprintf(stderr, "FALHOU: %s deveria retornar -1\n", description);
        failures++;
        return;
    }

    for (i = buffer_size; i < buffer_size + 4; i++) {
        if (buffer[i] != 0xAA) {
            fprintf(stderr, "FALHOU: %s escreveu alem do buffer (byte %d)\n",
                    description, (int)i);
            failures++;
            return;
        }
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void check_invalid_domain(const char *description, const char *domain)
{
    uint8_t buffer[DNS_MAX_MSG];

    if (build_query(buffer, sizeof(buffer), domain, 0x1234) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

int main(void)
{
    /* (a) unb.br, id 0x1234: header + QNAME + QTYPE MX + QCLASS IN = 24 bytes */
    static const uint8_t unb_br[] = {
        0x12, 0x34,             /* ID */
        0x01, 0x00,             /* flags: RD */
        0x00, 0x01,             /* QDCOUNT */
        0x00, 0x00,             /* ANCOUNT */
        0x00, 0x00,             /* NSCOUNT */
        0x00, 0x00,             /* ARCOUNT */
        3, 'u', 'n', 'b', 2, 'b', 'r', 0,
        0x00, 0x0f,             /* QTYPE MX */
        0x00, 0x01              /* QCLASS IN */
    };

    /* (b) mail.google.com, id 0xBEEF: 12 + 17 + 4 = 33 bytes */
    static const uint8_t mail_google_com[] = {
        0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        4, 'm', 'a', 'i', 'l',
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x0f, 0x00, 0x01
    };

    check_query("consulta MX para unb.br (id 0x1234)",
                "unb.br", 0x1234, unb_br, sizeof(unb_br));
    check_query("consulta MX para mail.google.com (id 0xBEEF)",
                "mail.google.com", 0xBEEF, mail_google_com, sizeof(mail_google_com));

    /* (c) buffer de 20 bytes: header (12) + QNAME (8) cabem, QTYPE/QCLASS nao */
    check_small_buffer("buffer de 20 bytes para unb.br", "unb.br", 20);
    check_small_buffer("buffer menor que o header", "unb.br", 11);

    /* (d) dominio invalido */
    check_invalid_domain("dominio com rotulo vazio", "unb..br");

    if (failures != 0) {
        fprintf(stderr, "%d teste(s) das Fases 3-4 falharam.\n", failures);
        return 1;
    }

    printf("Todos os testes das Fases 3-4 passaram.\n");
    return 0;
}
