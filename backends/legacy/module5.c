#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void xor_stream_crypt(const unsigned char* in, unsigned char* out,
                             const unsigned char* key, const unsigned char* iv,
                             size_t len);

static char *base64_encode(const unsigned char *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = (char *)malloc(out_len);
    if (!out) return NULL;
    int written = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    if (written < 0) {
        free(out);
        return NULL;
    }
    out[written] = '\0';
    return out;
}

static unsigned char *base64_decode(const char *text, size_t *out_len) {
    size_t in_len = strlen(text);
    size_t max_out = 3 * ((in_len + 3) / 4);
    unsigned char *out = (unsigned char *)malloc(max_out + 1);
    if (!out) return NULL;
    int decoded = EVP_DecodeBlock(out, (const unsigned char *)text, (int)in_len);
    if (decoded < 0) {
        free(out);
        return NULL;
    }
    while (decoded > 0 && out[decoded - 1] == '\0') {
        decoded--;
    }
    out[decoded] = '\0';
    *out_len = decoded;
    return out;
}

static int derive_bytes(const char *password, const char *salt, unsigned char *output, size_t out_len) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char*)salt, strlen(salt), 10000, EVP_sha256(), (int)out_len, output);
}

static void print_error_and_exit(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static void do_hash(const char *password, const char *salt) {
    unsigned char derived[32];
    if (!derive_bytes(password, salt, derived, sizeof(derived))) {
        print_error_and_exit("hash failed");
    }
    char *encoded = base64_encode(derived, sizeof(derived));
    if (!encoded) print_error_and_exit("base64 encode failed");
    printf("%s", encoded);
    free(encoded);
}

static void do_derive(const char *password, const char *salt) {
    unsigned char derived[32];
    if (!derive_bytes(password, salt, derived, sizeof(derived))) {
        print_error_and_exit("derive failed");
    }
    char *encoded = base64_encode(derived, sizeof(derived));
    if (!encoded) print_error_and_exit("base64 encode failed");
    printf("%s", encoded);
    free(encoded);
}

static void do_encrypt(const char *plaintext, const char *base64key) {
    size_t key_len = 0;
    unsigned char *key = base64_decode(base64key, &key_len);
    if (!key || key_len == 0) print_error_and_exit("invalid key");
    size_t pt_len = strlen(plaintext);
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) print_error_and_exit("random generation failed");
    unsigned char *ciphertext = (unsigned char *)malloc(pt_len);
    if (!ciphertext) print_error_and_exit("malloc failed");
    xor_stream_crypt((const unsigned char *)plaintext, ciphertext, key, iv, pt_len);
    size_t blob_len = sizeof(iv) + pt_len;
    unsigned char *blob = (unsigned char *)malloc(blob_len);
    if (!blob) print_error_and_exit("malloc failed");
    memcpy(blob, iv, sizeof(iv));
    memcpy(blob + sizeof(iv), ciphertext, pt_len);
    char *encoded = base64_encode(blob, blob_len);
    if (!encoded) print_error_and_exit("base64 encode failed");
    printf("%s", encoded);
    free(ciphertext);
    free(blob);
    free(encoded);
    free(key);
}

static void do_decrypt(const char *ciphertext_base64, const char *base64key) {
    size_t key_len = 0;
    unsigned char *key = base64_decode(base64key, &key_len);
    if (!key || key_len == 0) print_error_and_exit("invalid key");
    size_t blob_len = 0;
    unsigned char *blob = base64_decode(ciphertext_base64, &blob_len);
    if (!blob || blob_len <= 16) print_error_and_exit("invalid ciphertext");
    unsigned char iv[16];
    memcpy(iv, blob, sizeof(iv));
    size_t payload_len = blob_len - sizeof(iv);
    unsigned char *plaintext = (unsigned char *)malloc(payload_len + 1);
    if (!plaintext) print_error_and_exit("malloc failed");
    xor_stream_crypt(blob + sizeof(iv), plaintext, key, iv, payload_len);
    plaintext[payload_len] = '\0';
    printf("%s", plaintext);
    free(plaintext);
    free(blob);
    free(key);
}

static void do_generate(const char *length_text) {
    int length = atoi(length_text);
    if (length <= 0) length = 12;
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    size_t setlen = strlen(charset);
    unsigned char *randbuf = (unsigned char *)malloc(length);
    if (!randbuf) print_error_and_exit("malloc failed");
    if (RAND_bytes(randbuf, length) != 1) print_error_and_exit("random generation failed");
    for (int i = 0; i < length; i++) {
        char ch = charset[randbuf[i] % setlen];
        putchar(ch);
    }
    free(randbuf);
}

static void do_strength(const char *password) {
    int score = 0;
    int hasLower = 0, hasUpper = 0, hasDigit = 0, hasSymbol = 0;
    size_t len = strlen(password);
    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (c >= 'a' && c <= 'z') hasLower = 1;
        else if (c >= 'A' && c <= 'Z') hasUpper = 1;
        else if (c >= '0' && c <= '9') hasDigit = 1;
        else hasSymbol = 1;
    }
    score += hasLower + hasUpper + hasDigit + hasSymbol;
    if (len >= 12) score++;
    printf("%d", score);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: module5 <command> ...\n");
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "hash") == 0 && argc == 4) {
        do_hash(argv[2], argv[3]);
    } else if (strcmp(cmd, "derive") == 0 && argc == 4) {
        do_derive(argv[2], argv[3]);
    } else if (strcmp(cmd, "encrypt") == 0 && argc == 4) {
        do_encrypt(argv[2], argv[3]);
    } else if (strcmp(cmd, "decrypt") == 0 && argc == 4) {
        do_decrypt(argv[2], argv[3]);
    } else if (strcmp(cmd, "generate") == 0 && argc == 3) {
        do_generate(argv[2]);
    } else if (strcmp(cmd, "strength") == 0 && argc == 3) {
        do_strength(argv[2]);
    } else {
        fprintf(stderr, "invalid module5 command\n");
        return 1;
    }
    return 0;
}
