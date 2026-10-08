# Trabalho 01 — Cliente DNS (consultas MX)

Fundamentos de Redes de Computadores — Prof. Tiago Alves — FCTE/UnB

## Integrantes

| Nome | Matrícula |
|---|---|
| Luiza Maluf Amorim| 221008294|
| Mateus de Castro Santos| 222015195|
| | |
| | |

## Sistema operacional

macOS (arm64), onde foi desenvolvido e testado, e Linux (Debian 12), onde foi verificado e testado também.

## Ambiente de desenvolvimento

- Linguagem C (padrão C11) e `make`.
- Compiladores: Apple clang 21 (macOS) e gcc 13.5 (Linux, em contêiner Docker).
- Editor: VS Code.

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

O teste da Fase 13 roda os quatro cenários do enunciado contra servidores DNS
reais (8.8.8.8 e 1.1.1.1) e, por isso, precisa de internet com acesso à porta
UDP 53. Ele não faz parte de `make test`:

```sh
make integration
```

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

- Apenas IPv4 e apenas UDP: respostas maiores que 512 bytes (flag TC) não são
  tratadas e resultam em "Nao foi possível coletar entrada MX".
- Os MX são impressos na ordem recebida, sem ordenar pela preferência.
- Nome de domínio com ponto final (`unb.br.`) é rejeitado como inválido.
- Um MX com exchange `.` ("null MX", RFC 7505) é tratado como domínio sem MX.
- `make integration` depende dos dados DNS publicados no momento do teste.
