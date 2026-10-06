CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = meu_cliente
SRCS    = src/main.c src/query.c src/net.c src/parse.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c src/dns.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
