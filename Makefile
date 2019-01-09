ARGON2_SRC = src/argon2/src/core.c src/argon2/src/argon2.c src/argon2/src/ref.c src/argon2/src/thread.c src/argon2/src/encoding.c src/argon2/src/blake2/blake2b.c
AES_SRC = src/aes/aes.c
SALSA20_SRC = src/salsa20/salsa20.c
CHACHA20_SRC = src/chacha/chacha.c src/chacha/poly1305.c
MAIN_SRC = src/main.c src/encrypt_v1.c src/decrypt_v1.c src/crypto_random.c src/getopt.c src/hexdump.c src/getpass.c
SRC = $(MAIN_SRC) $(AES_SRC) $(ARGON2_SRC) $(SALSA20_SRC) $(CHACHA20_SRC)

INCLUDES=-Isrc/argon2/include -Isrc/argon2/src/blake2
CFLAGS = -Wall -g -O3 $(INCLUDES)
LDFLAGS = -lpthread
TARGET = vsencrypt
AES_TEST = aes_test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

.PHONY: test_aes test_decryption_exist_files test_encryption

test: all test_aes test_decryption_exist_files test_encryption

test_aes: $(AES_TEST)
	./$(AES_TEST)

test_decryption_exist_files:
	./scripts/test_decryption.sh

test_encryption:
	./scripts/test_encryption.sh

$(AES_TEST): src/aes/aes.c src/aes/aes.h src/aes/aes_test.c
	$(CC) -Wall -o $(AES_TEST) src/aes/aes.c src/aes/aes_test.c

.PHONY: clean

clean:
	rm -f $(TARGET) $(AES_TEST)
