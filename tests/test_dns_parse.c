#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"

/* Fases 7-11: interpretacao da resposta DNS com dados de teste fixos.
 * Nenhum caso abre socket; as respostas sao arrays montados a mao (RFC 1035 4.1). */

static int failures = 0;

/* ---------- Fase 7: header da resposta ---------- */

static void print_header(const dns_header_t *hdr)
{
    printf("  Transaction ID: %u | QR: %u | RCODE: %u | Questions: %u | "
           "Answers: %u | Authority: %u | Additional: %u\n",
           hdr->id, DNS_FLAG_QR(hdr->flags), DNS_RCODE(hdr->flags),
           hdr->qdcount, hdr->ancount, hdr->nscount, hdr->arcount);
}

static void check_header(const char *description, const uint8_t *msg, size_t len,
                         uint16_t id, uint16_t flags, uint16_t qd, uint16_t an,
                         uint16_t ns, uint16_t ar)
{
    dns_header_t hdr;

    memset(&hdr, 0xFF, sizeof(hdr));

    if (parse_header(msg, len, &hdr) != 0) {
        fprintf(stderr, "FALHOU: %s (parse_header retornou erro)\n", description);
        failures++;
        return;
    }

    if (hdr.id != id || hdr.flags != flags || hdr.qdcount != qd ||
        hdr.ancount != an || hdr.nscount != ns || hdr.arcount != ar) {
        fprintf(stderr, "FALHOU: %s\n"
                        "  obtido:   id=%04x flags=%04x qd=%u an=%u ns=%u ar=%u\n"
                        "  esperado: id=%04x flags=%04x qd=%u an=%u ns=%u ar=%u\n",
                description,
                hdr.id, hdr.flags, hdr.qdcount, hdr.ancount, hdr.nscount, hdr.arcount,
                id, flags, qd, an, ns, ar);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
    print_header(&hdr);
}

static void check_header_rejected(const char *description, const uint8_t *msg,
                                  size_t len)
{
    dns_header_t hdr;

    if (parse_header(msg, len, &hdr) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void test_fase7_header(void)
{
    /* Resposta tipica de um resolvedor recursivo: QR=1, RD=1, RA=1, RCODE=0
     * (flags 0x8180); 1 pergunta, 1 resposta, 0 autoridade, 1 adicional.
     * A question vem junto para a mensagem ter mais de 12 bytes. */
    static const uint8_t resposta_ok[] = {
        0xab, 0x74,             /* ID 43892 */
        0x81, 0x80,             /* flags */
        0x00, 0x01,             /* QDCOUNT */
        0x00, 0x01,             /* ANCOUNT */
        0x00, 0x00,             /* NSCOUNT */
        0x00, 0x01,             /* ARCOUNT */
        3, 'u', 'n', 'b', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01
    };

    /* NXDOMAIN: flags 0x8183 (RCODE 3); 1 pergunta, 0 respostas, 1 autoridade. */
    static const uint8_t resposta_nxdomain[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
    };

    /* Contagens com os dois bytes significativos, para conferir a ordem
     * (network byte order): QD=0x0100=256, AN=0x0102=258, NS=0x00ff=255, AR=0x1000=4096. */
    static const uint8_t resposta_contagens[] = {
        0xff, 0xff, 0x80, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0xff, 0x10, 0x00
    };

    uint8_t query[DNS_MAX_MSG];
    int qlen;

    check_header("header de resposta com 1 answer",
                 resposta_ok, sizeof(resposta_ok), 0xab74, 0x8180, 1, 1, 0, 1);
    check_header("header NXDOMAIN",
                 resposta_nxdomain, sizeof(resposta_nxdomain), 0x1234, 0x8183, 1, 0, 1, 0);
    check_header("header com contagens multi-byte",
                 resposta_contagens, sizeof(resposta_contagens),
                 0xffff, 0x8000, 256, 258, 255, 4096);

    check_header_rejected("mensagem com 11 bytes", resposta_ok, 11);
    check_header_rejected("mensagem vazia", resposta_ok, 0);
    check_header_rejected("mensagem nula", NULL, DNS_HEADER_LEN);

    /* Ida e volta com build_query: o Transaction ID e os campos fixados pelo
     * enunciado devem ser lidos de volta exatamente como foram gravados. */
    qlen = build_query(query, sizeof(query), "unb.br", 0x1234);
    if (qlen < 0) {
        fprintf(stderr, "FALHOU: build_query nao montou a consulta de referencia\n");
        failures++;
    } else {
        check_header("header da consulta montada por build_query",
                     query, (size_t)qlen, 0x1234, 0x0100, 1, 0, 0, 0);
    }
}

/* ---------- Fase 8: bit QR e codigo de resposta (RCODE) ---------- */

static void check_status(const char *description, const uint8_t *resp, size_t len,
                         dns_status_t expected)
{
    mx_record_t mx[DNS_MAX_MX];
    int count = -1;
    dns_status_t status = parse_response(resp, len, mx, DNS_MAX_MX, &count);

    if (status != expected || count != 0) {
        fprintf(stderr, "FALHOU: %s (status %d, count %d; esperado status %d, count 0)\n",
                description, (int)status, count, (int)expected);
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
}

/* Question "foo.br" tipo MX classe IN, usada em todas as respostas abaixo. */
#define QUESTION_FOO_BR 3, 'f', 'o', 'o', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01

static void test_fase8_rcode(void)
{
    /* NXDOMAIN (RCODE 3) com um registro SOA na secao de autoridade, como um
     * resolvedor real devolve. A autoridade nao e lida pelo parser. */
    static const uint8_t nxdomain_soa[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        QUESTION_FOO_BR,
        0xc0, 0x0c,             /* NAME -> ponteiro para "foo.br" */
        0x00, 0x06,             /* TYPE SOA */
        0x00, 0x01,             /* CLASS IN */
        0x00, 0x00, 0x0e, 0x10, /* TTL 3600 */
        0x00, 0x1b,             /* RDLENGTH 27 */
        2, 'n', 's', 0xc0, 0x0c,            /* MNAME ns.foo.br */
        0xc0, 0x0c,                         /* RNAME */
        0x00, 0x00, 0x00, 0x01,             /* SERIAL */
        0x00, 0x00, 0x0e, 0x10,             /* REFRESH */
        0x00, 0x00, 0x03, 0x84,             /* RETRY */
        0x00, 0x09, 0x3a, 0x80,             /* EXPIRE */
        0x00, 0x00, 0x00, 0x3c              /* MINIMUM */
    };

    /* NOERROR (RCODE 0) sem nenhuma resposta: dominio existe, sem MX. */
    static const uint8_t nodata[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    /* SERVFAIL (RCODE 2) e REFUSED (RCODE 5): falha de coleta. */
    static const uint8_t servfail[] = {
        0x12, 0x34, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };
    static const uint8_t refused[] = {
        0x12, 0x34, 0x81, 0x85, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    /* QR = 0: e uma consulta, nao uma resposta. */
    static const uint8_t qr_zero[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    check_status("NXDOMAIN com SOA na autoridade",
                 nxdomain_soa, sizeof(nxdomain_soa), DNS_ERR_NXDOMAIN);
    check_status("NXDOMAIN truncado no meio da autoridade",
                 nxdomain_soa, 12 + 12 + 6, DNS_ERR_NXDOMAIN);
    check_status("NXDOMAIN so com o header",
                 nxdomain_soa, DNS_HEADER_LEN, DNS_ERR_NXDOMAIN);
    check_status("NOERROR sem respostas (sem MX)",
                 nodata, sizeof(nodata), DNS_ERR_NO_MX);
    check_status("SERVFAIL (RCODE 2) e falha de coleta",
                 servfail, sizeof(servfail), DNS_ERR_MALFORMED);
    check_status("REFUSED (RCODE 5) e falha de coleta",
                 refused, sizeof(refused), DNS_ERR_MALFORMED);
    check_status("QR = 0 (consulta ecoada) e malformada",
                 qr_zero, sizeof(qr_zero), DNS_ERR_MALFORMED);
    check_status("mensagem com 11 bytes e malformada",
                 nodata, 11, DNS_ERR_MALFORMED);
    check_status("mensagem vazia e malformada",
                 nodata, 0, DNS_ERR_MALFORMED);
}

/* ---------- Fase 9: leitura de nomes, com compressao ---------- */

static void check_name(const char *description, const uint8_t *msg, size_t msglen,
                       size_t offset, const char *expected, int expected_consumed)
{
    char out[DNS_MAX_NAME];
    int consumed;

    memset(out, 0x7F, sizeof(out));
    consumed = read_name(msg, msglen, offset, out, sizeof(out));

    if (consumed != expected_consumed || strcmp(out, expected) != 0) {
        fprintf(stderr, "FALHOU: %s\n  obtido:   \"%s\" (consumiu %d)\n"
                        "  esperado: \"%s\" (consumiu %d)\n",
                description, consumed < 0 ? "(erro)" : out, consumed,
                expected, expected_consumed);
        failures++;
        return;
    }

    printf("PASSOU: %s -> \"%s\" (%d bytes na posicao original)\n",
           description, out, consumed);
}

static void check_name_rejected(const char *description, const uint8_t *msg,
                                size_t msglen, size_t offset, size_t outlen)
{
    /* Sentinela depois de outlen: read_name nunca pode escrever la. */
    char out[DNS_MAX_NAME + 4];

    memset(out, 0x7F, sizeof(out));

    if (read_name(msg, msglen, offset, out, outlen) != -1) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado\n", description);
        failures++;
        return;
    }

    for (size_t i = outlen; i < outlen + 4 && i < sizeof(out); i++) {
        if (out[i] != 0x7F) {
            fprintf(stderr, "FALHOU: %s escreveu alem de outlen\n", description);
            failures++;
            return;
        }
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void test_fase9_read_name(void)
{
    /* Mensagem com header, "unb.br" em 12, e nomes comprimidos depois:
     *   20: 04 'm' 'a' 'i' 'l' C0 0C          -> mail.unb.br   (7 bytes)
     *   27: 02 'f' 'g' C0 0C                  -> fg.unb.br     (5 bytes)
     *   32: 03 'w' 'w' 'w' C0 1B              -> www.fg.unb.br (6 bytes, 2 saltos)
     *   38: C0 0C                             -> unb.br        (2 bytes)
     *   40: 00                                -> raiz          (1 byte) */
    static const uint8_t msg[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3, 'u', 'n', 'b', 2, 'b', 'r', 0,
        4, 'm', 'a', 'i', 'l', 0xc0, 0x0c,
        2, 'f', 'g', 0xc0, 0x0c,
        3, 'w', 'w', 'w', 0xc0, 0x1b,
        0xc0, 0x0c,
        0x00
    };

    static const uint8_t simples[] = { 3, 'u', 'n', 'b', 2, 'b', 'r', 0 };

    /* Casos invalidos */
    static const uint8_t rotulo_64[] = { 0x40, 'a', 0 };
    static const uint8_t reservado[] = { 0x80, 'a', 0 };
    static const uint8_t ponteiro_frente[] = { 0xc0, 0x04, 0, 0, 3, 'u', 'n', 'b', 0 };
    static const uint8_t ponteiro_self[] = { 0xc0, 0x00, 0 };
    static const uint8_t ponteiro_fora[] = { 3, 'u', 'n', 'b', 0, 0xff, 0xff };
    static const uint8_t ponteiro_truncado[] = { 3, 'u', 'n', 'b', 0, 0xc0 };
    static const uint8_t sem_terminador[] = { 3, 'u', 'n', 'b', 2, 'b', 'r' };
    static const uint8_t rotulo_curto[] = { 3, 'u', 'n' };

    /* 5 rotulos de 63 'a': 319 caracteres reconstruidos, acima de 255. */
    uint8_t longo[5 * 64 + 1];
    for (int i = 0; i < 5; i++) {
        longo[i * 64] = 63;
        memset(longo + i * 64 + 1, 'a', 63);
    }
    longo[5 * 64] = 0;

    check_name("nome simples em offset 0", simples, sizeof(simples), 0, "unb.br", 8);
    check_name("nome simples dentro da mensagem", msg, sizeof(msg), 12, "unb.br", 8);
    check_name("ponteiro puro (C0 0C)", msg, sizeof(msg), 38, "unb.br", 2);
    check_name("rotulo seguido de ponteiro", msg, sizeof(msg), 20, "mail.unb.br", 7);
    check_name("dois saltos encadeados", msg, sizeof(msg), 32, "www.fg.unb.br", 6);
    check_name("nome raiz (00)", msg, sizeof(msg), 40, "", 1);
    check_name("mensagem terminando exatamente no fim do nome", msg, 20, 12, "unb.br", 8);

    check_name_rejected("rotulo com tamanho 64", rotulo_64, sizeof(rotulo_64), 0, DNS_MAX_NAME);
    check_name_rejected("byte de tamanho reservado (10xxxxxx)", reservado, sizeof(reservado), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para frente", ponteiro_frente, sizeof(ponteiro_frente), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para si mesmo", ponteiro_self, sizeof(ponteiro_self), 0, DNS_MAX_NAME);
    check_name_rejected("ponteiro para fora da mensagem", ponteiro_fora, sizeof(ponteiro_fora), 5, DNS_MAX_NAME);
    check_name_rejected("ponteiro truncado (so 1 byte)", ponteiro_truncado, sizeof(ponteiro_truncado), 5, DNS_MAX_NAME);
    check_name_rejected("nome sem terminador", sem_terminador, sizeof(sem_terminador), 0, DNS_MAX_NAME);
    check_name_rejected("rotulo maior que a mensagem", rotulo_curto, sizeof(rotulo_curto), 0, DNS_MAX_NAME);
    check_name_rejected("offset igual a msglen", simples, sizeof(simples), sizeof(simples), DNS_MAX_NAME);
    check_name_rejected("nome reconstruido com mais de 255 caracteres", longo, sizeof(longo), 0, DNS_MAX_NAME);
    check_name_rejected("buffer de saida menor que o nome", simples, sizeof(simples), 0, 6);
}

/* ---------- Fase 10: percorrer os Resource Records ---------- */

/* Resposta REAL do 8.8.8.8 para "unb.br" tipo MX (capturada com tests/dns_live).
 * Bytes 0-11 header, 12-23 question, 24-35 cabecalho do registro, 36-73 RDATA. */
static const uint8_t real_unb[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    3, 'u', 'n', 'b', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01,
    0xc0, 0x0c,                 /* NAME -> ponteiro para "unb.br" */
    0x00, 0x0f,                 /* TYPE MX */
    0x00, 0x01,                 /* CLASS IN */
    0x00, 0x00, 0x08, 0xbd,     /* TTL 2237 */
    0x00, 0x26,                 /* RDLENGTH 38 */
    0x00, 0x00,                 /* preference 0 */
    6, 'u', 'n', 'b', '-', 'b', 'r', 4, 'm', 'a', 'i', 'l',
    10, 'p', 'r', 'o', 't', 'e', 'c', 't', 'i', 'o', 'n',
    7, 'o', 'u', 't', 'l', 'o', 'o', 'k', 3, 'c', 'o', 'm', 0
};

/* Dois registros: um CNAME (TYPE 5) e depois um MX. Para chegar no MX o
 * parser precisa medir certo o tamanho do primeiro. O TTL do CNAME usa quatro
 * bytes diferentes (0x01020304) para conferir a ordem dos bytes. */
static const uint8_t cname_e_mx[] = {
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    3, 'u', 'n', 'b', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01,       /* 12-23 */
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,      /* 24-33 */
    0x00, 0x05, 2, 'm', 'x', 0xc0, 0x0c,                             /* 34-40 */
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,      /* 41-50 */
    0x00, 0x07, 0x00, 0x0a, 2, 'm', 'x', 0xc0, 0x0c                  /* 51-59 */
};

static void print_rr(int n, const dns_rr_t *rr)
{
    printf("  Answer %d: TYPE: %u | CLASS: %u | TTL: %u | RDLENGTH: %u | RDATA em %zu\n",
           n, rr->type, rr->rrclass, rr->ttl, rr->rdlength, rr->rdata_offset);
}

/* Confere o registro rrs[i] campo a campo. */
static int rr_equals(const dns_rr_t *rr, uint16_t type, uint16_t rrclass,
                     uint32_t ttl, uint16_t rdlength, size_t rdata_offset)
{
    return rr->type == type && rr->rrclass == rrclass && rr->ttl == ttl &&
           rr->rdlength == rdlength && rr->rdata_offset == rdata_offset;
}

static void check_answers_rejected(const char *description, const uint8_t *msg,
                                   size_t len)
{
    dns_rr_t rrs[DNS_MAX_RR];
    int count = -1;

    if (parse_answers(msg, len, rrs, DNS_MAX_RR, &count) != -1 || count != 0) {
        fprintf(stderr, "FALHOU: %s deveria ser rejeitado (count %d)\n", description, count);
        failures++;
        return;
    }

    printf("PASSOU: rejeicao de %s\n", description);
}

static void test_fase10_records(void)
{
    /* Resposta sem nenhuma answer (dominio existe, sem MX). */
    static const uint8_t sem_answers[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR
    };

    dns_rr_t rrs[DNS_MAX_RR];
    int count;
    int pos;

    /* --- resposta real --- */
    memset(rrs, 0, sizeof(rrs));
    count = -1;
    if (parse_answers(real_unb, sizeof(real_unb), rrs, DNS_MAX_RR, &count) != 0 ||
        count != 1 || !rr_equals(&rrs[0], DNS_TYPE_MX, DNS_CLASS_IN, 2237, 38, 36) ||
        rrs[0].rdata_offset + rrs[0].rdlength != sizeof(real_unb)) {
        fprintf(stderr, "FALHOU: resposta real do 8.8.8.8 para unb.br\n");
        failures++;
    } else {
        printf("PASSOU: resposta real do 8.8.8.8 -> 1 registro MX (TYPE 15)\n");
        print_rr(1, &rrs[0]);
    }

    /* --- CNAME antes do MX --- */
    memset(rrs, 0, sizeof(rrs));
    count = -1;
    if (parse_answers(cname_e_mx, sizeof(cname_e_mx), rrs, DNS_MAX_RR, &count) != 0 ||
        count != 2 ||
        !rr_equals(&rrs[0], 5, DNS_CLASS_IN, 0x01020304, 5, 36) ||
        !rr_equals(&rrs[1], DNS_TYPE_MX, DNS_CLASS_IN, 60, 7, 53) ||
        rrs[1].rdata_offset + rrs[1].rdlength != sizeof(cname_e_mx)) {
        fprintf(stderr, "FALHOU: CNAME seguido de MX\n");
        failures++;
    } else {
        printf("PASSOU: CNAME seguido de MX -> 2 registros, o MX encontrado no lugar certo\n");
        print_rr(1, &rrs[0]);
        print_rr(2, &rrs[1]);
    }

    /* --- zero answers --- */
    count = -1;
    if (parse_answers(sem_answers, sizeof(sem_answers), rrs, DNS_MAX_RR, &count) != 0 ||
        count != 0) {
        fprintf(stderr, "FALHOU: resposta sem answers\n");
        failures++;
    } else {
        printf("PASSOU: resposta sem answers -> 0 registros\n");
    }

    /* --- limite do array: guarda so os primeiros, mas valida todos --- */
    memset(rrs, 0, sizeof(rrs));
    count = -1;
    if (parse_answers(cname_e_mx, sizeof(cname_e_mx), rrs, 1, &count) != 0 || count != 1 ||
        rrs[0].type != 5) {
        fprintf(stderr, "FALHOU: max_rrs menor que ANCOUNT\n");
        failures++;
    } else {
        printf("PASSOU: max_rrs = 1 guarda so o primeiro registro\n");
    }
    check_answers_rejected("registro fora do limite guardado, mas truncado",
                           cname_e_mx, sizeof(cname_e_mx) - 1);

    /* --- skip_questions isolada --- */
    pos = skip_questions(real_unb, sizeof(real_unb), DNS_HEADER_LEN, 1);
    if (pos != 24) {
        fprintf(stderr, "FALHOU: skip_questions retornou %d (esperado 24)\n", pos);
        failures++;
    } else {
        printf("PASSOU: skip_questions pula 1 question e para no byte 24\n");
    }
    pos = skip_questions(real_unb, sizeof(real_unb), DNS_HEADER_LEN, 0);
    if (pos != DNS_HEADER_LEN) {
        fprintf(stderr, "FALHOU: skip_questions com 0 questions retornou %d\n", pos);
        failures++;
    } else {
        printf("PASSOU: skip_questions com 0 questions nao move o cursor\n");
    }

    /* --- mensagens quebradas: nenhuma pode ler fora do buffer --- */
    check_answers_rejected("question sem QTYPE/QCLASS (cortada no nome)",
                           real_unb, 12 + 8);
    check_answers_rejected("question com QCLASS cortado", real_unb, 12 + 8 + 3);
    check_answers_rejected("QDCOUNT maior que as questions presentes",
                           sem_answers, sizeof(sem_answers) - 4);
    check_answers_rejected("ANCOUNT=1 mas mensagem acaba na question", real_unb, 24);
    check_answers_rejected("registro cortado no meio do NAME", real_unb, 25);
    check_answers_rejected("registro cortado no meio do TTL", real_unb, 24 + 2 + 2 + 2 + 2);
    check_answers_rejected("registro sem o RDLENGTH inteiro", real_unb, 24 + 2 + 8 + 1);
    check_answers_rejected("RDATA cortado em 1 byte", real_unb, sizeof(real_unb) - 1);
    check_answers_rejected("mensagem so com o header e ANCOUNT=1",
                           real_unb, DNS_HEADER_LEN);
    check_answers_rejected("mensagem com 11 bytes", real_unb, 11);
    check_answers_rejected("mensagem nula", NULL, 0);

    {
        /* RDLENGTH exagerado: diz 0xffff mas sobram poucos bytes. */
        uint8_t exagerado[sizeof(real_unb)];

        memcpy(exagerado, real_unb, sizeof(real_unb));
        exagerado[34] = 0xff;
        exagerado[35] = 0xff;
        check_answers_rejected("RDLENGTH maior que o resto da mensagem",
                               exagerado, sizeof(exagerado));
    }

    {
        /* NAME do registro com ponteiro para frente (invalido para read_name). */
        uint8_t ponteiro_ruim[sizeof(real_unb)];

        memcpy(ponteiro_ruim, real_unb, sizeof(real_unb));
        ponteiro_ruim[24] = 0xc0;
        ponteiro_ruim[25] = 0x40;
        check_answers_rejected("NAME do registro com ponteiro invalido",
                               ponteiro_ruim, sizeof(ponteiro_ruim));
    }

    /* --- integracao com parse_response --- */
    check_status("parse_response: NOERROR sem answers continua sem MX",
                 sem_answers, sizeof(sem_answers), DNS_ERR_NO_MX);
    check_status("parse_response: answers truncadas viram resposta malformada",
                 real_unb, sizeof(real_unb) - 1, DNS_ERR_MALFORMED);
}

/* ---------- Fase 11: extrair o MX ---------- */

static void check_mx(const char *description, const uint8_t *resp, size_t len,
                     int max_mx, dns_status_t expected_status, int expected_count,
                     const uint16_t *prefs, const char *const *names)
{
    mx_record_t mx[DNS_MAX_MX];
    int count = -1;
    int ok;
    dns_status_t status;

    memset(mx, 0, sizeof(mx));
    status = parse_response(resp, len, mx, max_mx, &count);
    ok = status == expected_status && count == expected_count;
    for (int i = 0; ok && i < expected_count; i++) {
        ok = mx[i].preference == prefs[i] && strcmp(mx[i].exchange, names[i]) == 0;
    }

    if (!ok) {
        fprintf(stderr, "FALHOU: %s (status %d, count %d; esperado status %d, count %d)\n",
                description, (int)status, count, (int)expected_status, expected_count);
        for (int i = 0; i < count && i < DNS_MAX_MX; i++) {
            fprintf(stderr, "  obtido[%d]: preference %u, exchange \"%s\"\n",
                    i, mx[i].preference, mx[i].exchange);
        }
        failures++;
        return;
    }

    printf("PASSOU: %s\n", description);
    for (int i = 0; i < count; i++) {
        printf("  Preference: %u | Exchange: %s\n", mx[i].preference, mx[i].exchange);
    }
}

static void test_fase11_mx(void)
{
    /* Resposta REAL do 8.8.8.8 para "google.com" tipo MX: o nome do exchange
     * dentro do RDATA e "smtp" + ponteiro C0 0C para "google.com". */
    static const uint8_t real_google[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x0f, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x9f, 0x00, 0x09,
        0x00, 0x0a, 4, 's', 'm', 't', 'p', 0xc0, 0x0c
    };

    /* Resposta REAL do 8.8.8.8 para "fga.unb.br" tipo MX: o dominio existe, mas a
     * unica answer e um CNAME (TYPE 5), e ha um SOA na autoridade. Nao ha MX. */
    static const uint8_t real_fga[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        3, 'f', 'g', 'a', 3, 'u', 'n', 'b', 2, 'b', 'r', 0, 0x00, 0x0f, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x6d, 0x00, 0x07,
        4, 'f', 'c', 't', 'e', 0xc0, 0x10,
        0xc0, 0x10, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x04, 0x32, 0x00, 0x28,
        4, 'd', 'n', 's', '1', 0xc0, 0x10,
        10, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r', 0xc0, 0x10,
        0x78, 0xc3, 0xd8, 0x41, 0x00, 0x00, 0x38, 0x40, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x0e, 0x10
    };

    /* Um MX para "foo.br": preference 10, exchange "mx1" + ponteiro para "foo.br".
     * Bytes 24-35 cabecalho do registro (CLASS em 28-29, RDLENGTH em 34-35) e
     * 36-43 RDATA (ponteiro em 42-43). Os casos quebrados abaixo alteram copias. */
    static const uint8_t um_mx[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR,
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x08,
        0x00, 0x0a, 3, 'm', 'x', '1', 0xc0, 0x0c
    };

    /* Dois MX: preference 10 "mx1.foo.br" e preference 20 "mx2.foo.br". */
    static const uint8_t dois_mx[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR,
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x08,
        0x00, 0x0a, 3, 'm', 'x', '1', 0xc0, 0x0c,
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x08,
        0x00, 0x14, 3, 'm', 'x', '2', 0xc0, 0x0c
    };

    /* "Null MX" (RFC 7505): preference 0 e exchange "." (so o byte 00). */
    static const uint8_t null_mx[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        QUESTION_FOO_BR,
        0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03,
        0x00, 0x00, 0x00
    };

    static const uint16_t pref_unb[]    = { 0 };
    static const char *const nome_unb[] = { "unb-br.mail.protection.outlook.com" };
    static const uint16_t pref_google[]    = { 10 };
    static const char *const nome_google[] = { "smtp.google.com" };
    static const uint16_t pref_cname[]    = { 10 };
    static const char *const nome_cname[] = { "mx.unb.br" };
    static const uint16_t pref_dois[]    = { 10, 20 };
    static const char *const nome_dois[] = { "mx1.foo.br", "mx2.foo.br" };

    uint8_t quebrado[sizeof(um_mx)];

    check_mx("resposta real unb.br -> unb-br.mail.protection.outlook.com",
             real_unb, sizeof(real_unb), DNS_MAX_MX, DNS_OK, 1, pref_unb, nome_unb);
    check_mx("resposta real google.com -> exchange com ponteiro dentro do RDATA",
             real_google, sizeof(real_google), DNS_MAX_MX, DNS_OK, 1,
             pref_google, nome_google);
    check_mx("CNAME antes do MX e ignorado, so o MX e devolvido",
             cname_e_mx, sizeof(cname_e_mx), DNS_MAX_MX, DNS_OK, 1,
             pref_cname, nome_cname);
    check_mx("resposta real fga.unb.br (so CNAME) -> sem MX",
             real_fga, sizeof(real_fga), DNS_MAX_MX, DNS_ERR_NO_MX, 0, NULL, NULL);
    check_mx("dois MX sao devolvidos na ordem da resposta",
             dois_mx, sizeof(dois_mx), DNS_MAX_MX, DNS_OK, 2, pref_dois, nome_dois);
    check_mx("max_mx = 1 devolve so o primeiro MX",
             dois_mx, sizeof(dois_mx), 1, DNS_OK, 1, pref_dois, nome_dois);
    check_mx("max_mx = 0 nao guarda nada",
             dois_mx, sizeof(dois_mx), 0, DNS_ERR_NO_MX, 0, NULL, NULL);
    check_mx("null MX (exchange \".\") equivale a sem MX",
             null_mx, sizeof(null_mx), DNS_MAX_MX, DNS_ERR_NO_MX, 0, NULL, NULL);

    /* MX de outra classe (3 = CHAOS) nao e MX da Internet. */
    memcpy(quebrado, um_mx, sizeof(um_mx));
    quebrado[29] = 3;
    check_mx("MX de classe diferente de IN e ignorado",
             quebrado, sizeof(quebrado), DNS_MAX_MX, DNS_ERR_NO_MX, 0, NULL, NULL);

    /* RDLENGTH 1: nem cabe a preference. */
    memcpy(quebrado, um_mx, sizeof(um_mx));
    quebrado[35] = 1;
    check_mx("RDATA de MX com 1 byte (curto demais)",
             quebrado, sizeof(quebrado), DNS_MAX_MX, DNS_ERR_MALFORMED, 0, NULL, NULL);

    /* RDLENGTH 2: tem a preference mas falta o nome. */
    memcpy(quebrado, um_mx, sizeof(um_mx));
    quebrado[35] = 2;
    check_mx("RDATA de MX so com a preference (sem exchange)",
             quebrado, sizeof(quebrado), DNS_MAX_MX, DNS_ERR_MALFORMED, 0, NULL, NULL);

    /* RDLENGTH 4: o nome "mx1..." comecaria no RDATA mas terminaria depois dele. */
    memcpy(quebrado, um_mx, sizeof(um_mx));
    quebrado[35] = 4;
    check_mx("exchange que ultrapassa o fim do RDATA",
             quebrado, sizeof(quebrado), DNS_MAX_MX, DNS_ERR_MALFORMED, 0, NULL, NULL);

    /* Ponteiro do exchange apontando para frente (invalido). */
    memcpy(quebrado, um_mx, sizeof(um_mx));
    quebrado[42] = 0xc0;
    quebrado[43] = 0x40;
    check_mx("exchange com ponteiro de compressao invalido",
             quebrado, sizeof(quebrado), DNS_MAX_MX, DNS_ERR_MALFORMED, 0, NULL, NULL);

    /* Mensagem cortada no meio do RDATA do MX. */
    check_mx("MX com RDATA cortado no fim da mensagem",
             um_mx, sizeof(um_mx) - 1, DNS_MAX_MX, DNS_ERR_MALFORMED, 0, NULL, NULL);

    {
        mx_record_t mx[1];
        int count = -1;

        if (parse_response(um_mx, sizeof(um_mx), mx, 1, NULL) != DNS_ERR_MALFORMED ||
            parse_response(um_mx, sizeof(um_mx), NULL, 1, &count) != DNS_ERR_MALFORMED) {
            fprintf(stderr, "FALHOU: ponteiros nulos em parse_response\n");
            failures++;
        } else {
            printf("PASSOU: rejeicao de ponteiros nulos em parse_response\n");
        }
    }
}

int main(void)
{
    test_fase7_header();
    test_fase8_rcode();
    test_fase9_read_name();
    test_fase10_records();
    test_fase11_mx();

    if (failures != 0) {
        fprintf(stderr, "%d teste(s) do parser falharam.\n", failures);
        return 1;
    }

    printf("Todos os testes das Fases 7-11 passaram.\n");
    return 0;
}
