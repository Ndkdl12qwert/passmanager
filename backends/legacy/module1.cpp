#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <cstring>
#include <sstream>
#include <iomanip>

std::string base64_encode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);
    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return result;
}

std::string base64_decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);

    std::vector<char> buffer(input.size());
    int length = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_free_all(bio);

    if (length <= 0) {
        return std::string();
    }
    return std::string(buffer.data(), length);
}

std::string pbkdf2_hash(const std::string& password, const std::string& salt, int iterations = 10000) {
    unsigned char key[32];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), static_cast<int>(salt.length()),
                           iterations, EVP_sha256(), 32, key)) {
        return std::string();
    }

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(2) << static_cast<int>(key[i]);
    }
    return ss.str();
}

std::string pbkdf2_key(const std::string& password, const std::string& salt, int iterations = 10000) {
    unsigned char key[32];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), static_cast<int>(salt.length()),
                           iterations, EVP_sha256(), 32, key)) {
        return std::string();
    }
    return std::string(reinterpret_cast<char*>(key), 32);
}

bool aes_encrypt(const std::string& plaintext, const std::string& key_b64, std::string& output) {
    std::string key = base64_decode(key_b64);
    if (key.size() != 32) {
        return false;
    }

    std::vector<unsigned char> iv(16);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           reinterpret_cast<const unsigned char*>(key.data()), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result(reinterpret_cast<char*>(iv.data()), iv.size());
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    output = base64_encode(result);
    return true;
}

bool aes_decrypt(const std::string& ciphertext_b64, const std::string& key_b64, std::string& output) {
    std::string key = base64_decode(key_b64);
    if (key.size() != 32) {
        return false;
    }

    std::string ciphertext = base64_decode(ciphertext_b64);
    if (ciphertext.size() < 16) {
        return false;
    }

    const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data());
    const unsigned char* encrypted_data = reinterpret_cast<const unsigned char*>(ciphertext.data() + 16);
    int encrypted_len = static_cast<int>(ciphertext.size() - 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           reinterpret_cast<const unsigned char*>(key.data()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    std::vector<unsigned char> plaintext(encrypted_len + AES_BLOCK_SIZE);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data, encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    output.assign(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    return true;
}

std::string generate_random_password(int length = 12) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{};:,.<>/?\\|";
    std::string password;
    password.reserve(length);

    std::vector<unsigned char> random_bytes(length);
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
        return std::string();
    }

    for (int i = 0; i < length; ++i) {
        password.push_back(chars[random_bytes[i] % chars.size()]);
    }
    return password;
}

int check_password_strength(const std::string& password) {
    int strength = 0;
    if (password.length() >= 8) strength++;
    if (password.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos) strength++;
    if (password.find_first_of("abcdefghijklmnopqrstuvwxyz") != std::string::npos) strength++;
    if (password.find_first_of("0123456789") != std::string::npos) strength++;
    if (password.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != std::string::npos) strength++;
    return strength;
}

int main(int argc, char* argv[]) {
    if (RAND_poll() != 1) {
        std::cerr << "ERROR: RAND_poll failed" << std::endl;
        return 1;
    }

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [args...]" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  hash <password> <salt>" << std::endl;
        std::cout << "  derive <password> <salt>" << std::endl;
        std::cout << "  encrypt <plaintext> <base64key>" << std::endl;
        std::cout << "  decrypt <ciphertext> <base64key>" << std::endl;
        std::cout << "  generate [length]" << std::endl;
        std::cout << "  strength <password>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "hash" && argc == 4) {
        std::string password = argv[2];
        std::string salt = argv[3];
        std::string result = pbkdf2_hash(password, salt);
        if (result.empty()) return 1;
        std::cout << result;
    } else if (command == "derive" && argc == 4) {
        std::string password = argv[2];
        std::string salt = argv[3];
        std::string key = pbkdf2_key(password, salt);
        if (key.empty()) return 1;
        std::cout << base64_encode(key);
    } else if (command == "encrypt" && argc == 4) {
        std::string plaintext = argv[2];
        std::string key_b64 = argv[3];
        std::string output;
        if (!aes_encrypt(plaintext, key_b64, output)) {
            return 1;
        }
        std::cout << output;
    } else if (command == "decrypt" && argc == 4) {
        std::string ciphertext = argv[2];
        std::string key_b64 = argv[3];
        std::string output;
        if (!aes_decrypt(ciphertext, key_b64, output)) {
            return 1;
        }
        std::cout << output;
    } else if (command == "generate") {
        int length = (argc >= 3) ? std::stoi(argv[2]) : 12;
        std::string result = generate_random_password(length);
        if (result.empty()) return 1;
        std::cout << result;
    } else if (command == "strength" && argc == 3) {
        std::string password = argv[2];
        std::cout << check_password_strength(password);
    } else {
        std::cerr << "ERROR: Invalid command or arguments" << std::endl;
        return 1;
    }

    return 0;
}
