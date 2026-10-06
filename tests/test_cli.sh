#!/bin/sh

set -eu

program=${1:-./meu_cliente}

fail()
{
    printf 'FALHOU: %s\n' "$1" >&2
    exit 1
}

expected_valid='Dominio: unb.br
Servidor DNS: 8.8.8.8'
actual=$("$program" unb.br 8.8.8.8) || fail 'execucao com argumentos validos'
[ "$actual" = "$expected_valid" ] || fail 'saida dos argumentos validos'

check_invalid()
{
    if actual=$("$program" "$@" 2>&1); then
        fail 'comando invalido terminou com sucesso'
    fi

    expected="Uso: $program <dominio> <ip_servidor_dns>"
    [ "$actual" = "$expected" ] || fail 'mensagem de uso incorreta'
}

check_invalid
check_invalid unb.br
check_invalid unb.br 8.8.8.8 argumento_extra

printf 'Todos os testes das fases 0 e 1 passaram.\n'
