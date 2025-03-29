#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// File Operations Functions
void writeFile(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }
    fprintf(file, "%s", content);
    fclose(file);
    printf("File written successfully.\n");
}

void readFile(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("File not found!\n");
        return;
    }
    char ch;
    while ((ch = fgetc(file)) != EOF)
        putchar(ch);
    fclose(file);
    printf("\n");
}

void renameFile(const char *oldname, const char *newname) {
    if (rename(oldname, newname) == 0)
        printf("File renamed successfully.\n");
    else
        printf("Error renaming file!\n");
}

void deleteFile(const char *filename) {
    if (remove(filename) == 0)
        printf("File deleted successfully.\n");
    else
        printf("Error deleting file!\n");
}

// Security Functions
void hashPassword(const char *password, unsigned char *hash) {
    SHA256((const unsigned char*)password, strlen(password), hash);
}

void registerUser() {
    char username[50], password[50];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);
    
    hashPassword(password, hash);
    FILE *file = fopen("users.db", "a");
    fprintf(file, "%s ", username);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        fprintf(file, "%02x", hash[i]);
    fprintf(file, "\n");
    fclose(file);
    printf("User registered successfully!\n");
}

int generateOTP() {
    srand(time(NULL));
    return rand() % 900000 + 100000;  // 6-digit OTP
}

void verifyOTP() {
    int otp = generateOTP();
    printf("Your OTP is: %d\n", otp);
    
    int userOTP;
    printf("Enter OTP: ");
    scanf("%d", &userOTP);
    
    if (userOTP == otp)
        printf("Authentication successful!\n");
    else
        printf("Authentication failed!\n");
}

void encryptFile(const char *input, const char *output, const unsigned char *key) {
    FILE *in = fopen(input, "rb");
    if (in == NULL) {
        printf("Error opening input file!\n");
        return;
    }
    
    FILE *out = fopen(output, "wb");
    if (out == NULL) {
        printf("Error creating output file!\n");
        fclose(in);
        return;
    }
    
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey);
    
    unsigned char buffer[AES_BLOCK_SIZE];
    size_t bytesRead;
    
    while ((bytesRead = fread(buffer, 1, AES_BLOCK_SIZE, in)) > 0) {
        // Pad the buffer if needed
        if (bytesRead < AES_BLOCK_SIZE) {
            memset(buffer + bytesRead, 0, AES_BLOCK_SIZE - bytesRead);
        }
        
        AES_encrypt(buffer, buffer, &encryptKey);
        fwrite(buffer, 1, AES_BLOCK_SIZE, out);
    }
    
    fclose(in);
    fclose(out);
    printf("File encrypted successfully.\n");
}

// Access Control Function
typedef struct {
    char username[50];
    char role[10];
} User;

void checkAccess(User user, const char *operation) {
    if (strcmp(user.role, "admin") == 0 || 
       (strcmp(user.role, "user") == 0 && strcmp(operation, "read") == 0))
        printf("Access granted for %s\n", operation);
    else
        printf("Access denied for %s\n", operation);
}

// Security Scan Function
void scanFile(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("File not found!\n");
        return;
    }
    
    char buffer[256];
    int threatFound = 0;
    
    while (fgets(buffer, sizeof(buffer), file)) {
        if (strstr(buffer, "malware") || strstr(buffer, "virus")) {
            printf("Threat detected!\n");
            threatFound = 1;
        }
    }
    
    if (!threatFound) {
        printf("No threats detected.\n");
    }
    
    fclose(file);
}

// Main function
int main() {
    printf("===== Secure File Management System =====\n\n");
    
    int choice;
    char filename[100], newname[100], content[1000];
    unsigned char key[16] = "securekey123456";
    User currentUser = {"admin", "admin"};  // Default user for demonstration
    
    do {
        printf("\nMenu:\n");
        printf("1. Register New User\n");
        printf("2. Authenticate with OTP\n");
        printf("3. Write File\n");
        printf("4. Read File\n");
        printf("5. Rename File\n");
        printf("6. Encrypt File\n");
        printf("7. Scan File for Threats\n");
        printf("8. Delete File\n");
        printf("9. Check Access Rights\n");
        printf("0. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();  // Consume newline
        
        switch (choice) {
            case 1:
                registerUser();
                break;
                
            case 2:
                verifyOTP();
                break;
                
            case 3:
                printf("Enter filename: ");
                scanf("%s", filename);
                printf("Enter content: ");
                getchar();  // Consume newline
                fgets(content, sizeof(content), stdin);
                content[strcspn(content, "\n")] = 0;  // Remove trailing newline
                writeFile(filename, content);
                break;
                
            case 4:
                printf("Enter filename: ");
                scanf("%s", filename);
                readFile(filename);
                break;
                
            case 5:
                printf("Enter current filename: ");
                scanf("%s", filename);
                printf("Enter new filename: ");
                scanf("%s", newname);
                renameFile(filename, newname);
                break;
                
            case 6:
                printf("Enter filename to encrypt: ");
                scanf("%s", filename);
                printf("Enter output filename: ");
                scanf("%s", newname);
                encryptFile(filename, newname, key);
                break;
                
            case 7:
                printf("Enter filename to scan: ");
                scanf("%s", filename);
                scanFile(filename);
                break;
                
            case 8:
                printf("Enter filename to delete: ");
                scanf("%s", filename);
                deleteFile(filename);
                break;
                
            case 9:
                printf("Enter operation (read/write/delete): ");
                scanf("%s", content);
                checkAccess(currentUser, content);
                break;
                
            case 0:
                printf("Exiting...\n");
                break;
                
            default:
                printf("Invalid choice!\n");
        }
    } while (choice != 0);
    
    return 0;
}