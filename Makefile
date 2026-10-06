CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = meu_cliente
SRCS    = src/main.c src/query.c src/net.c src/parse.c
OBJS    = $(SRCS:.c=.o)
TEST_DNS_NAME = tests/test_dns_name

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c src/dns.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_DNS_NAME)

$(TEST_DNS_NAME): tests/test_dns_name.c src/query.c src/dns.h
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_dns_name.c src/query.c

test: $(TARGET) $(TEST_DNS_NAME)
	sh tests/test_cli.sh ./$(TARGET)
	./$(TEST_DNS_NAME)

.PHONY: all clean test
