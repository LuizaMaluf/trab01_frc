#include "dns.h"

int send_and_receive(const char *server_ip, const uint8_t *query, size_t qlen,
                     uint8_t *resp, size_t resplen, uint16_t id)
{
    /* TODO (Pessoa 2):
     * - socket(AF_INET, SOCK_DGRAM, 0)
     * - inet_pton para server_ip, porta htons(DNS_PORT)
     * - setsockopt SO_RCVTIMEO = DNS_TIMEOUT_SEC
     * - loop de DNS_MAX_TRIES: sendto + recvfrom; validar ID da resposta
     * - close(socket) em todos os caminhos */
    (void)server_ip; (void)query; (void)qlen; (void)resp; (void)resplen; (void)id;
    return -1;
}
