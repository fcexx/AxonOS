# libnss_axonos - NSS module for AxonOS SYS_resolve
# Requires glibc headers. Build on host (Linux) and add libnss_axonos.so.2 to initfs.

CFLAGS := -shared -fPIC -O2 -Wall
TARGET := libnss_axonos.so.2

all: $(TARGET)

$(TARGET): nss_axonos.c
	gcc $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -D -m 755 $(TARGET) $(DESTDIR)/lib/$(TARGET)

.PHONY: all clean install
