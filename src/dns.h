#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNS_PORT        53
#define DNS_MAX_MSG     512   /* limite de mensagem DNS sobre UDP (RFC 1035 4.2.1) */
#define DNS_TIMEOUT_SEC 2
#define DNS_MAX_TRIES   3
#define DNS_TYPE_MX     15
#define DNS_CLASS_IN    1
#define DNS_MAX_NAME    256
#define DNS_MAX_WIRE_NAME 255
#define DNS_MAX_MX      16

typedef enum {
    DNS_OK = 0,
    DNS_ERR_NXDOMAIN,     /* RCODE 3: dominio nao existe */
    DNS_ERR_NO_MX,        /* RCODE 0, mas nenhuma resposta TYPE 15 */
    DNS_ERR_NO_RESPONSE,  /* timeout apos DNS_MAX_TRIES tentativas */
    DNS_ERR_MALFORMED     /* resposta invalida / outro RCODE */
} dns_status_t;

typedef struct {
    uint16_t preference;
    char exchange[DNS_MAX_NAME];
} mx_record_t;

/* ---------- query.c (Pessoa 1) ----------
 * Converte "unb.br" para 03 'u' 'n' 'b' 02 'b' 'r' 00.
 * Retorna o tamanho codificado ou -1 se o dominio for invalido ou nao couber. */
int encode_dns_name(const char *domain, uint8_t *buf, size_t buflen);

/*
 * Monta header (12 bytes) + question (QNAME, QTYPE=MX, QCLASS=IN) em buf.
 * Retorna o tamanho da mensagem ou -1 em erro. */
int build_query(uint8_t *buf, size_t buflen, const char *domain, uint16_t id);

/* ---------- net.c (Pessoa 2) ----------
 * Envia uma consulta UDP para server_ip:53 e recebe uma resposta.
 * Aguarda ate DNS_TIMEOUT_SEC por tentativa e faz ate DNS_MAX_TRIES envios.
 * Retorna o tamanho da resposta ou -1 em erro/ausencia de resposta. */
int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id);

/* Mesmo transporte com porta configuravel para testes locais. */
int send_and_receive_to(const char *server_ip, uint16_t port,
                        const uint8_t *query, size_t qlen,
                        uint8_t *resp, size_t resplen, uint16_t id);

/* ---------- parse.c (Pessoa 3) ----------
 * Le um nome a partir de msg[offset], seguindo ponteiros de compressao (0xC0).
 * Escreve o nome em formato "a.b.c" em out.
 * Retorna quantos bytes o nome ocupa na posicao ORIGINAL (para avancar o cursor),
 * ou -1 em erro. */
int read_name(const uint8_t *msg, size_t msglen, size_t offset,
              char *out, size_t outlen);

/* Interpreta a resposta: verifica RCODE, pula a question, percorre as
 * answers e extrai os registros MX (TYPE 15) em mx[0..*count-1]. */
dns_status_t parse_response(const uint8_t *resp, size_t len,
                            mx_record_t *mx, int max_mx, int *count);

#endif
