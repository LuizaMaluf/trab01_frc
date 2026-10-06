Desenvolvimento de forma **incremental**, com uma regra: **nenhuma fase avança sem um teste claro dizendo que a anterior funciona**. Isso evita chegar no final com um pacote DNS quebrado sem saber se o problema está no header, no socket ou no parser.

O objetivo final é um programa que receba `domínio + IP do servidor DNS`, construa manualmente uma consulta DNS do tipo MX, envie via UDP para a porta 53, aguarde a resposta e extraia o servidor de e-mail. trabalho_01_2026.02

## Visão geral do desenvolvimento

```text
✅ FASE 0 — Preparação
      ↓
✅ FASE 1 — Interface de linha de comando
      ↓
✅ FASE 2 — Codificação do domínio ────────┐
      ↓                                    │
FASE 3 — Construção do Header DNS          │  podem existir
      ↓                                    │  trabalhos em paralelo
FASE 4 — Montagem do pacote completo ──────┘
      ↓
FASE 5 — Socket UDP + envio
      ↓
FASE 6 — Timeout + retransmissão
      ↓
FASE 7 — Parser do Header da resposta ─────┐
      ↓                                     │
FASE 8 — Parser dos registros DNS           │ paralelo parcial
      ↓                                     │
FASE 9 — Extração do MX ────────────────────┘
      ↓
FASE 10 — Tratamento dos erros
      ↓
FASE 11 — Integração e testes
      ↓
FASE 12 — Documentação e entrega
```

Como o trabalho dá 100% da pontuação para **C ou Rust**, 95% para C++/Go e 90% para linguagens interpretadas/Java, a linguagem recomendada é **C**, especialmente porque o exercício envolve bytes, sockets e protocolo. trabalho_01_2026.02

---

# Fase 0 — Preparar o projeto ✅

Antes de DNS propriamente dito.

Adotar uma estrutura como:

```text
dns-client/
├── src/
│   ├── main.c
│   ├── dns_query.c
│   ├── dns_query.h
│   ├── dns_parser.c
│   ├── dns_parser.h
│   ├── udp_client.c
│   └── udp_client.h
├── tests/
├── Makefile
└── README.md
```

Dividir conceitualmente em três componentes:

```text
dns_query
    ↓
constrói mensagem DNS

udp_client
    ↓
envia/recebe

dns_parser
    ↓
interpreta resposta
```

### Teste para concluir a fase

```bash
make
./meu_cliente
```

O programa deve compilar sem warnings importantes e executar.

---

# Fase 1 — Ler os argumentos ✅

O trabalho exige algo como:

```bash
./meu_cliente unb.br 8.8.8.8
```

O primeiro argumento é o domínio e o segundo é o servidor DNS. trabalho_01_2026.02

Nesta fase, não utilizar comunicação de rede.

O programa deve imprimir:

```text
Dominio: unb.br
Servidor DNS: 8.8.8.8
```

Também deve ser testado:

```bash
./meu_cliente
```

com a apresentação de uma mensagem como:

```text
Uso: ./meu_cliente <dominio> <servidor_dns>
```

### Critério de aceite

```bash
./meu_cliente unb.br 8.8.8.8
```

captura corretamente ambos os valores.

---

# Fase 2 — Codificar o domínio em formato DNS ✅

Aqui começa o protocolo.

Implementar uma função como:

```c
int encode_dns_name(
    const char *domain,
    unsigned char *buffer
);
```

Entrada:

```text
unb.br
```

Saída em bytes:

```text
03 75 6e 62 02 62 72 00
```

Que representa:

```text
03 "unb"
02 "br"
00
```

Testar **essa função isoladamente**.

Casos:

```text
unb.br
google.com
mail.google.com
```

Por exemplo:

```text
mail.google.com

04 mail
06 google
03 com
00
```

### Critério de aceite

Imprimir o buffer em hexadecimal e conferir manualmente.

Ainda **não é necessário utilizar socket**.

---

# Fase 3 — Construir apenas o Header DNS

Essa fase pode ser desenvolvida **em paralelo com a Fase 2**.

O header possui:

```text
Transaction ID
Flags
QDCOUNT
ANCOUNT
NSCOUNT
ARCOUNT
```

O enunciado determina:

```text
Transaction ID → aleatório, 16 bits
Flags          → 0x0100
QDCOUNT        → 0x0001
ANCOUNT        → 0x0000
NSCOUNT        → 0x0000
ARCOUNT        → 0x0000
```

trabalho_01_2026.02

O resultado é um header de:

```text
12 bytes
```

Pode ser criada uma função como:

```c
int build_dns_header(
    unsigned char *buffer,
    uint16_t transaction_id
);
```

### Teste

Fixar temporariamente:

```text
Transaction ID = 0x1234
```

e imprimir:

```text
12 34 01 00 00 01 00 00 00 00 00 00
```

Se aparecer exatamente isso, o header está correto.

Depois, retornar à geração aleatória do ID.

---

## Trabalho paralelo inicial

As fases 2 e 3 são praticamente independentes e podem ser executadas em paralelo. Após a conclusão, seus resultados devem ser integrados.

---

# Fase 4 — Construir a Question e o pacote completo

Nesta fase, reunir:

```text
HEADER
+
QNAME
+
QTYPE
+
QCLASS
```

O trabalho determina:

```text
QTYPE  = MX
QCLASS = IN
```

trabalho_01_2026.02

Numericamente:

```text
MX = 15
IN = 1
```

Portanto, para `unb.br`:

```text
HEADER
│
├── Transaction ID
├── 0100
├── 0001
├── 0000
├── 0000
└── 0000

QUESTION
│
├── 03 "unb"
├── 02 "br"
├── 00
├── 00 0F      ← MX
└── 00 01      ← IN
```

### Teste importante

Imprimir **todo o pacote em hexadecimal**.

Por exemplo:

```text
12 34
01 00
00 01
00 00
00 00
00 00
03 75 6e 62
02 62 72
00
00 0f
00 01
```

Ainda sem internet.

Com esse resultado, há uma **consulta DNS válida em memória**.

Registrar um checkpoint no controle de versão:

```text
feat: build DNS MX query
```

---

# Fase 5 — Criar o socket UDP

Agora a rede entra.

O enunciado exige UDP. trabalho_01_2026.02

Em C, utilizar conceitualmente:

```c
socket(AF_INET, SOCK_DGRAM, 0);
```

Montar o destino:

```text
IP: 8.8.8.8
Porta: 53
```

Depois:

```c
sendto(...)
```

### Primeiro teste

Ainda não interpretar a resposta.

Exibir inicialmente apenas:

```text
consulta enviada: X bytes
```

Depois, chamar:

```c
recvfrom(...)
```

e imprimir:

```text
recebemos 87 bytes
```

O recebimento de uma resposta comprova o fluxo:

```text
pacote criado
      ↓
UDP
      ↓
DNS
      ↓
resposta voltou
```

---

# Fase 6 — Timeout e três tentativas

O trabalho exige:

- esperar 2 segundos;
- tentar novamente se não houver resposta;
- no máximo 3 tentativas. trabalho_01_2026.02

Implementar essa lógica separadamente.

### Teste de sucesso

```bash
./meu_cliente unb.br 8.8.8.8
```

Deve responder, preferencialmente, na primeira tentativa.

### Teste de timeout

O próprio enunciado dá:

```bash
./meu_cliente unb.br 1.2.3.4
```

Resultado final esperado:

```text
Nao foi possível coletar entrada MX para unb.br
```

trabalho_01_2026.02

Durante o desenvolvimento, podem ser exibidos logs como:

```text
Tentativa 1...
Timeout.

Tentativa 2...
Timeout.

Tentativa 3...
Timeout.
```

Remover os logs antes da entrega.

---

## Trabalho paralelo de rede e parsing

O desenvolvimento da comunicação de rede deve contemplar `socket` UDP, `sendto`, `recvfrom`, timeout e três tentativas. Em paralelo, o parser do pacote DNS pode ser desenvolvido com respostas salvas em arrays ou arquivos de teste, sem dependência da conclusão do socket. Ao final, os bytes recebidos pela camada de rede devem alimentar o parser.

---

# Fase 7 — Interpretar o header da resposta

Não extrair o MX imediatamente.

Primeiro, interpretar somente os 12 primeiros bytes.

Implementar uma função como:

```c
parse_dns_header(response);
```

Extraindo:

```text
Transaction ID
Flags
QDCOUNT
ANCOUNT
NSCOUNT
ARCOUNT
```

Testar com a impressão de valores como:

```text
Transaction ID: 43892
Questions: 1
Answers: 1
Authority: 0
Additional: 1
```

### Teste essencial

O Transaction ID da resposta deve ser o mesmo da requisição.

Então:

```text
Query ID    = 12345
Response ID = 12345
```

Se forem diferentes, a resposta não corresponde à sua consulta.

---

# Fase 8 — Detectar domínio inexistente

Antes mesmo de procurar MX, interpretar as flags da resposta.

O exemplo exigido pelo trabalho é:

```bash
./meu_cliente imagdaskdasdasj.br 1.1.1.1
```

Resultado:

```text
Dominio imagdaskdasdasj.br nao encontrado
```

trabalho_01_2026.02

Criar uma etapa específica:

```text
Resposta chegou
      ↓
Header válido?
      ↓
Servidor respondeu domínio inexistente?
      ↓
sim → imprimir erro
```

Assim, evita-se misturar erro DNS com ausência de MX.

---

# Fase 9 — Criar uma função para ler nomes DNS

Essa merece uma fase própria.

É necessário transformar nomes presentes nos bytes da resposta novamente em:

```text
unb.br
```

ou:

```text
unb-br.mail.protection.outlook.com
```

Implementar conceitualmente uma função como:

```c
int read_dns_name(
    const unsigned char *message,
    int message_size,
    int offset,
    char *output
);
```

Essa função deve lidar inclusive com **compressão DNS**, caso a resposta utilize ponteiros.

Exemplo normal:

```text
03 unb 02 br 00
```

→

```text
unb.br
```

Exemplo comprimido:

```text
C0 0C
```

→ aponta para outra posição do pacote.

### Não avançar sem testar essa função adequadamente.

Praticamente todo o parser depende dessa função.

---

# Fase 10 — Percorrer os Resource Records

Nesta fase, processar as respostas propriamente ditas.

Cada registro contém conceitualmente:

```text
NAME
TYPE
CLASS
TTL
RDLENGTH
RDATA
```

O programa deve percorrer o buffer corretamente.

Por enquanto, não é necessário extrair o MX.

Imprimir:

```text
Answer 1:
TYPE: 15
CLASS: 1
TTL: ...
RDLENGTH: ...
```

### Critério de aceite

Para uma consulta MX válida, deve ser localizado pelo menos um:

```text
TYPE = 15
```

---

# Fase 11 — Extrair o MX

Agora sim.

Quando:

```text
TYPE == MX
```

interpretar o `RDATA`.

Para MX, há:

```text
Preference
Exchange
```

Exemplo conceitual:

```text
Preference: 10
Exchange: unb-br.mail.protection.outlook.com
```

O trabalho quer essencialmente o `Exchange`.

A saída deve seguir o formato:

```text
unb.br <> unb-br.mail.protection.outlook.com
```

Esse formato é exigido explicitamente. trabalho_01_2026.02

---

# Fase 12 — Diferenciar “não existe” de “não possui MX”

Isso é importante porque são casos diferentes.

### Caso A — domínio não existe

```text
imagdaskdasdasj.br
```

Resultado:

```text
Dominio imagdaskdasdasj.br nao encontrado
```

### Caso B — domínio existe, mas não possui MX

```text
fga.unb.br
```

Resultado:

```text
Dominio fga.unb.br nao possui entrada MX
```

trabalho_01_2026.02

Então a lógica fica:

```text
resposta DNS
   │
   ├── domínio inexistente
   │      └── "Dominio ... nao encontrado"
   │
   ├── domínio existe + encontrou MX
   │      └── imprime servidor
   │
   └── domínio existe + não encontrou MX
          └── "nao possui entrada MX"
```

---

# Fase 13 — Teste de integração completo

Nesta fase, substituir os testes isolados pelos quatro cenários fornecidos no enunciado.

### Teste 1 — sucesso

```bash
./meu_cliente unb.br 8.8.8.8
```

Esperado:

```text
unb.br <> ...
```

### Teste 2 — NXDOMAIN

```bash
./meu_cliente imagdaskdasdasj.br 1.1.1.1
```

Esperado:

```text
Dominio imagdaskdasdasj.br nao encontrado
```

### Teste 3 — sem MX

```bash
./meu_cliente fga.unb.br 8.8.8.8
```

Esperado:

```text
Dominio fga.unb.br nao possui entrada MX
```

### Teste 4 — DNS indisponível

```bash
./meu_cliente unb.br 1.2.3.4
```

Depois de três tentativas:

```text
Nao foi possível coletar entrada MX para unb.br
```

São justamente os cenários fornecidos no trabalho. trabalho_01_2026.02

---

# Fase 14 — Limpeza do código

Só depois de tudo funcionando.

Remover:

```text
printf("cheguei aqui")
printf("byte 37...")
printf("tentativa...")
```

que tenham sido usados para debug.

Organizar funções pequenas:

```text
encode_dns_name()
build_dns_query()
send_dns_query()
receive_dns_response()
parse_dns_header()
read_dns_name()
parse_mx_records()
```

Adicionar validações de limites do buffer, pois há manipulação direta de bytes.

---

# Fase 15 — Documentação

A documentação deve ser preparada com antecedência, pois vale **20% do trabalho**.

O professor exige documentação contendo:

- sistema operacional usado;
- ambiente de desenvolvimento;
- como construir;
- como executar;
- instruções de uso;
- limitações conhecidas. trabalho_01_2026.02

O `README.md` pode conter:

```markdown
# Cliente DNS MX

## Ambiente

macOS / Linux
GCC ...

## Compilação

make

## Execução

./meu_cliente <dominio> <servidor_dns>

Exemplo:

./meu_cliente unb.br 8.8.8.8

## Funcionamento

...

## Limitações

...
```

Não incluir executáveis; o trabalho pede apenas código-fonte e documentação. trabalho_01_2026.02

---

## Estratégia de integração

O desenvolvimento deve ocorrer em **blocos pequenos → integração → teste → novo bloco**. Essa estratégia antecipa a identificação de problemas de integração e mantém as fases paralelas independentes quando possível.

---

## Checkpoints no controle de versão

- [x] **Checkpoint 1**
  - programa compila;
  - argumentos funcionam.
- [ ] **Checkpoint 2 — Em andamento**
  - [x] QNAME correto;
  - [ ] header correto.
- [ ] **Checkpoint 3** — pacote DNS completo correto.
- [ ] **Checkpoint 4**
  - UDP envia;
  - UDP recebe.
- [ ] **Checkpoint 5** — timeout e três tentativas.
- [ ] **Checkpoint 6** — header da resposta interpretado.
- [ ] **Checkpoint 7** — nomes DNS decodificados.
- [ ] **Checkpoint 8** — registros DNS percorridos.
- [ ] **Checkpoint 9** — MX extraído.
- [ ] **Checkpoint 10** — todos os quatro casos do enunciado passam.

Não iniciar pela implementação integral do cliente DNS. A sequência deve começar com `unb.br → 03 unb 02 br 00`, seguir para o header, a montagem do pacote, o envio, o recebimento dos bytes e, por fim, a interpretação da resposta.

Esse desenvolvimento incremental permite identificar **qual componente falhou**, sem depurar protocolo, rede e parser simultaneamente.
