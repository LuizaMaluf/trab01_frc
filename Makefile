CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = meu_cliente
SRCS    = main.c query.c net.c parse.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c dns.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
