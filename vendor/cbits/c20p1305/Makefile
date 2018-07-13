CFLAGS := -Wall -Wextra

test: rfc7539_test
	./rfc7539_test

chacha20poly1305.o: chacha20poly1305.c chacha20.o poly1305.o
	$(CC) $(CFLAGS) -c -o $@ $<

chacha20.o: chacha_merged.c
	$(CC) $(CFLAGS) -c -o $@ $<

poly1305.o: poly1305-donna.c
	$(CC) $(CFLAGS) -DPOLY1305_16BIT -c -o $@ $<

rfc7539_test: rfc7539.c chacha20poly1305.o poly1305.o chacha20.o

.PHONY: test
