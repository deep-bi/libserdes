-include ../Makefile.config

PKGNAME=	libserdes-tests
BINNAME=	libserdes_tests

SRCS=	main-test.c \
        rest-test.c \
        serdes-test.c

OBJS= $(SRCS:.c=.o)

CPPFLAGS += -I../src
CFLAGS   += -Wall -Wextra -g

LIBS += ../src/libserdes.a \
        -lcurl -lz -ljansson -lrdkafka -lrdkafka++ -lavro -lssl -lcrypto -ldl -lrt -lpthread

all: $(BINNAME)

$(BINNAME): $(OBJS)
	@echo "Linking $@..."
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning test artifacts..."
	rm -f $(OBJS) $(BINNAME)

.PHONY: all check clean install

install:
	@echo "Nothing to install for tests"
