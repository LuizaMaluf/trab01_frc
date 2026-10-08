# Trabalho 01 — Cliente DNS (consultas MX)

Fundamentos de Redes de Computadores — Prof. Tiago Alves — FCTE/UnB

## Integrantes

| Nome | Matrícula |
|---|---|
| Luiza Maluf Amorim| 221008294|
| | |
| | |
| | |

## Sistema operacional

TODO

## Ambiente de desenvolvimento

TODO (compilador e versão, editor, ferramentas de teste: dig, Wireshark)

## Como construir

```sh
make
```

## Como testar

```sh
make test
```

O teste da Fase 5 troca uma consulta e uma resposta UDP em `127.0.0.1`,
usando uma porta local escolhida pelo sistema. Ele não depende de um
servidor DNS externo.

O teste da Fase 6 verifica a espera de dois segundos, a retransmissão
e o limite de três tentativas com esse mesmo tipo de servidor local.

O teste da Fase 12 (`tests/test_client.c`) roda o cliente completo contra um
servidor DNS falso em `127.0.0.1` e confere a saída de cada cenário: MX
encontrado, domínio inexistente, domínio sem MX, servidor que não responde,
erros do servidor e resposta inválida. Ele leva cerca de 6 segundos por causa
do cenário de timeout.

Para observar uma consulta real e os bytes retornados por um servidor DNS:

```sh
make tests/dns_live
./tests/dns_live unb.br 8.8.8.8
```

Esse comando imprime a consulta e a resposta em hexadecimal, seguidas dos
registros encontrados e dos MX extraídos.

## Como executar

```sh
./meu_cliente <dominio> <ip_servidor_dns>
```

## Telas (instruções de uso)

```
$ ./meu_cliente unb.br 8.8.8.8
unb.br <> unb-br.mail.protection.outlook.com

$ ./meu_cliente imagdaskdasdasj.br 1.1.1.1
Dominio imagdaskdasdasj.br nao encontrado

$ ./meu_cliente fga.unb.br 8.8.8.8
Dominio fga.unb.br nao possui entrada MX

$ ./meu_cliente unb.br 1.2.3.4
Nao foi possível coletar entrada MX para unb.br
```

## Limitações conhecidas

TODO
