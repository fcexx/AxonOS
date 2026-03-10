CC := gcc
CFLAGS := -Wall -O2 -fPIC
AR := ar
RANLIB := ranlib

LIB := libaxonos_resolve.a
OBJS := getaddrinfo.o

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB)

.PHONY: all clean
