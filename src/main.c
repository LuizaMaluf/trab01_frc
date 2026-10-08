#include <stdio.h>
#include "dns.h"

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dominio> <ip_servidor_dns>\n", argv[0]);
        return 1;
    }

    return run_client(stdout, argv[1], argv[2], DNS_PORT);
}
