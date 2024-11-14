#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>

// **************************************************************************
//                          MILESTONE 1

// Convert a single hex character to its decimal value
uint8_t hex_char_to_val(unsigned char h) {
    if (h >= '0' && h <= '9') {
        return h - '0';
    } else if (h >= 'a' && h <= 'f') {
        return h - 'a' + 10;
    } else if (h >= 'A' && h <= 'F') {
        return h - 'A' + 10;
    }
    return 0; // Should handle error cases if needed
}

uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {
    return (hex_char_to_val(h1) << 4) | hex_char_to_val(h2);
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {
    for (int i = 0; i < 32; i++) {
        hash[i] = hex_to_byte(hexstr[i*2], hexstr[i*2 + 1]);
    }
}

void test_hex_to_byte() {
    assert(hex_to_byte('c', '8') == 200);  // c8 in hex is 12*16 + 8 = 200
    assert(hex_to_byte('0', '3') == 3); // 03 in hex is 0*16 + 3 = 3
    assert(hex_to_byte('0', 'a') == 10); // 0a in hex is 0*16 + 10 = 10 
    assert(hex_to_byte('1', '0') == 16); // 10 in hex is 16
    printf("All hex_to_byte tests passed!\n");
}

void test_hexstr_to_hash() {
    char hexstr[65] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
    unsigned char hash[32];
    hexstr_to_hash(hexstr, hash);

    // Verifying first and last bytes
    assert(hash[0] == 0xa2);
    assert(hash[31] == 0xfd);

    // Prinf full hash for visual verification
    for (int i = 0; i < 32; i++) {
        char expected[3] = {hexstr[i*2], hexstr[i*2+1], '\0'};
        char actual[3];
        sprintf(actual, "%02x", hash[i]);
        assert(strcmp(expected, actual) == 0);
    }

    printf("All hexstr_to_hash tests passed!\n");
}

const int TESTING = 0;

// **************************************************************************
//                          MILESTONE 2

//Check if a password matches a given hash
int8_t check_password(char password[], unsigned char given_hash[32]) {
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];  
    SHA256((unsigned char*)password, strlen(password), computed_hash);
    // computed_hash is an array of 32 bytes (256 bits) that will store the SHA256 hash of the password we're checking

    // Compare the computed hash with the given hash
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (computed_hash[i] != given_hash[i]) {
            return 0;
        }
    }
    return 1;
}

void test_check_password() {
    char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    unsigned char given_hash[32];
    hexstr_to_hash(hash_as_hexstr, given_hash);

    assert(check_password("password", given_hash) == 1);
    assert(check_password("wrongpass", given_hash) == 0);
    printf("All check_password tests passed!\n");
}

// **************************************************************************
//                          MILESTONE 3

int8_t crack_password(char password[], unsigned char given_hash[32]) {
    // First try as-is
    if (check_password(password, given_hash)) {
        return 1;
    }

    size_t len = strlen(password);
    char original[1024];
    char current[1024];
    strcpy(original, password);
    strcpy(current, original);

    // Try single case changes
    for (size_t i = 0; i < len; i++) {
        strcpy(current, original);
        if (current[i] >= 'a' && current[i] <= 'z') {
            current[i] = current[i] - ('a' - 'A');
            if (check_password(current, given_hash)) {
                strcpy(password, current);
                return 1;
            }
        }
        else if (current[i] >= 'A' && current[i] <= 'Z') {
            current[i] = current[i] + ('a' - 'A');
            if (check_password(current, given_hash)) {
                strcpy(password, current);
                return 1;
            }
        }
    }

    // Try replacing each numeric digit
    for (size_t i = 0; i < len; i++) {
        strcpy(current, original);
        if (current[i] >= '0' && current[i] <= '9') {
            char original_digit = current[i];
            for (char digit = '0'; digit <= '9'; digit++) {
                if (digit != original_digit) {
                    current[i] = digit;
                    if (check_password(current, given_hash)) {
                        strcpy(password, current);
                        return 1;
                    }
                }
            }
        }
    }

    strcpy(password, original);
    return 0;
}


void test_crack_password() {
    // Test with "password" hash
    char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; 
    unsigned char given_hash[32];
    hexstr_to_hash(hash_as_hexstr, given_hash);
    
    char test_pass1[] = "password";
    printf("Testing exact match...\n");
    assert(crack_password(test_pass1, given_hash) == 1);
    assert(strcmp(test_pass1, "password") == 0);
    
    char test_pass2[] = "paSsword";
    printf("Testing lowercase conversion...\n");
    assert(crack_password(test_pass2, given_hash) == 1);
    assert(strcmp(test_pass2, "password") == 0);
    
    // Test with "Password" hash
    char upper_hash_str[] = "e7CF3EF4F17C3999A94F2C6F612E8A888E5B1026878E4E19398B23BD38EC221A";  // hash for "Password"
    unsigned char upper_hash[32];
    hexstr_to_hash(upper_hash_str, upper_hash);
    
    char test_pass3[] = "password";
    printf("Testing uppercase conversion...\n");
    int result = crack_password(test_pass3, upper_hash);
    printf("Result: %d\n", result);
    printf("Password after crack: %s\n", test_pass3);
    assert(result == 1);
    assert(strcmp(test_pass3, "Password") == 0);
    
    char test_pass4[] = "PASSword";
    printf("Testing no match possible...\n");
    assert(crack_password(test_pass4, given_hash) == 0);
    
    printf("All crack_password tests passed!\n");
}

void hash_to_hexstr(unsigned char hash[32], char hexstr[65]) {
    for (int i = 0; i < 32; i ++) {
        sprintf(&hexstr[i*2], "%02x", hash[i]);
    }
    hexstr[64] = '\0';
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <64-character-hex-hash>\n", argv[0]);
        return 1;
    }

    unsigned char target_hash[32];
    hexstr_to_hash(argv[1], target_hash);
    
    char password[1024];
    int found = 0;

    while (fgets(password, sizeof(password), stdin) != NULL) {
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len-1] = '\0';
        }

        if (crack_password(password, target_hash)) {
            unsigned char computed_hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char*)password, strlen(password), computed_hash);

            char hexstr[65];
            hash_to_hexstr(computed_hash, hexstr);
            printf("Found password: SHA256(%s) = %s\n", password, hexstr);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Did not find a matching password\n");
    }

    return 0;
}