#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>
#include <curl/curl.h>

#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$#@"
#define HASH_HAMMER_VERSION "1.1" 
#define VERSION_URL "https://raw.githubusercontent.com/TrixSec/Hash-Hammer/main/VERSION"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"

typedef struct {
    char *target_hash;
    int password_length;
    int thread_id;
    int total_threads;
    char *password_file;
} thread_args_t;

volatile int found = 0;
atomic_long checked_count = 0;
long total_combinations = 0;

void banner() {
    printf(CYAN "===============================\n");
    printf("     Hash-Hammer v1.1  \n");
    printf("     Hash Cracker      \n");
    printf("===============================\n" RESET);
}

void print_info_table() {
    printf(YELLOW "+-----------------------------------------------------------------+\n" RESET);
    printf(YELLOW "| " RESET "Author      : " GREEN "Trix Cyrus                    " YELLOW "|\n" RESET);
    printf(YELLOW "| " RESET "Developed By: " GREEN "Trixsec Org                   " YELLOW "|\n" RESET);
    printf(YELLOW "| " RESET "Telegram    : " GREEN "@Trixsec                      " YELLOW "|\n" RESET);
    printf(YELLOW "| " RESET "GitHub      : " GREEN "github.com/TrixSec/Hash-Hammer" YELLOW "|\n" RESET);
    printf(YELLOW "| " RESET "Supported   : " GREEN "MD5                           " YELLOW "|\n" RESET);
    printf(YELLOW "+-----------------------------------------------------------------+\n" RESET);
    printf("\n");
}

void display_options() {
    printf(YELLOW "\nOptions:\n");
    printf("--------------------------------\n");
    printf("| Mode | Description           |\n");
    printf("--------------------------------\n");
    printf("| 1    | Brute-force Mode      |\n");
    printf("| 2    | Password File Mode    |\n");
    printf("--------------------------------\n" RESET);
}

void compute_md5(const char *str, unsigned char *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, str, strlen(str));
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);
}

void md5_to_hex(const unsigned char *md5, char *md5_str) {
    for (int i = 0; i < 16; i++) {
        sprintf(md5_str + i * 2, "%02x", md5[i]);
    }
}

void brute_force(char *password, int position, int max_length, const char *target_hash) {
    if (found) return;
    if (position == max_length) {
        unsigned char digest[16];
        char md5_str[33];

        compute_md5(password, digest);
        md5_to_hex(digest, md5_str);

        atomic_fetch_add(&checked_count, 1);

        if (strcmp(md5_str, target_hash) == 0) {
            printf(GREEN "\nPassword found: %s\n" RESET, password);
            found = 1;
        }
        return;
    }

    for (int i = 0; i < strlen(CHARSET); i++) {
        password[position] = CHARSET[i];
        brute_force(password, position + 1, max_length, target_hash);
        if (found) return;
    }
}

void *thread_function_bruteforce(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    int charset_size = strlen(CHARSET);
    int chunk_size = charset_size / targs->total_threads;
    int start = targs->thread_id * chunk_size;
    int end = (targs->thread_id + 1) * chunk_size;

    char password[targs->password_length + 1];
    memset(password, 0, sizeof(password));

    for (int i = start; i < end && !found; i++) {
        password[0] = CHARSET[i];
        brute_force(password, 1, targs->password_length, targs->target_hash);
    }
    return NULL;
}

void *thread_function_file(void *args) {
    thread_args_t *targs = (thread_args_t *)args;
    FILE *file = fopen(targs->password_file, "r");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }
    char password[128];
    while (fgets(password, sizeof(password), file) && !found) {
        password[strcspn(password, "\n")] = 0; 
        unsigned char digest[16];
        char md5_str[33];

        compute_md5(password, digest);
        md5_to_hex(digest, md5_str);

        atomic_fetch_add(&checked_count, 1);

        if (strcmp(md5_str, targs->target_hash) == 0) {
            printf(GREEN "\nPassword found: %s\n" RESET, password);
            found = 1;
            break;
        }
    }
    fclose(file);
    return NULL;
}

void display_stats(clock_t start_time) {
    long previous_checked = 0;
    while (!found) {
        long checked = atomic_load(&checked_count);
        long remaining = total_combinations - checked;
        long speed = checked - previous_checked;
        previous_checked = checked;

        clock_t current_time = clock();
        double elapsed_time = (double)(current_time - start_time) / CLOCKS_PER_SEC;

        printf(YELLOW "\rChecked: %ld/%ld, Remaining: %ld, Speed: %ld passwords/sec, Time Elapsed: %.2f seconds" RESET, 
                checked, total_combinations, remaining, speed, elapsed_time);
        fflush(stdout);
        usleep(100000);
    }
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    FILE *file = (FILE *)userdata;
    size_t written = fwrite(ptr, size, nmemb, file);
    return written;
}

void check_for_updates() {
    CURL *curl;
    CURLcode res;
    FILE *version_file;
    char latest_version[32];

    curl = curl_easy_init();
    if(curl) {
        version_file = fopen("latest_version.txt", "w");
        if (!version_file) {
            fprintf(stderr, "[×] Error opening file to write latest version.\n");
            return;
        }

        curl_easy_setopt(curl, CURLOPT_URL, VERSION_URL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, version_file);
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "[×] Error fetching the latest version: %s\n", curl_easy_strerror(res));
            fclose(version_file);
            curl_easy_cleanup(curl);
            return;
        }

        fclose(version_file);
        curl_easy_cleanup(curl);

        version_file = fopen("latest_version.txt", "r");
        if (!version_file) {
            fprintf(stderr, "[×] Error opening version file.\n");
            return;
        }

        fgets(latest_version, sizeof(latest_version), version_file);
        fclose(version_file);
        latest_version[strcspn(latest_version, "\n")] = 0;  

        if (strcmp(HASH_HAMMER_VERSION, latest_version) != 0) {
            printf("[•] New version available: %s. Updating...\n", latest_version);
            system("git reset --hard HEAD");
            system("git pull");
            version_file = fopen("VERSION", "w");
            if (version_file) {
                fprintf(version_file, "%s\n", latest_version);
                fclose(version_file);
            }
            printf("[•] Update completed. Please rerun Hash-Hammer.\n");
            exit(0);
        } else {
            printf("[•] You are using the latest version: %s.\n", latest_version);
        }
    }
}

int main() {
    char target_hash[33];
    int password_length, thread_count, mode;
    char password_file[256] = {0};

    banner();
    check_for_updates();
    print_info_table();
    display_options();

    printf(CYAN "Enter the hash to crack: " RESET);
    scanf("%32s", target_hash);

    printf(CYAN "Choose mode: " RESET);
    scanf("%d", &mode);

    if (mode == 1) {
        printf(CYAN "Enter the password length: " RESET);
        scanf("%d", &password_length);
        total_combinations = 1;
        for (int i = 0; i < password_length; i++) {
            total_combinations *= strlen(CHARSET);
        }
    } else if (mode == 2) {
        printf(CYAN "Enter the path to the password file: " RESET);
        scanf("%s", password_file);
        total_combinations = 0;  
    } else {
        printf(RED "Invalid mode selected.\n" RESET);
        return 1;
    }

    printf(CYAN "Enter the number of threads: " RESET);
    scanf("%d", &thread_count);

    pthread_t threads[thread_count];
    thread_args_t targs[thread_count];

    pthread_t stats_thread;

    clock_t start_time = clock();
    
    pthread_create(&stats_thread, NULL, (void *)display_stats, (void *)start_time);

    for (int i = 0; i < thread_count; i++) {
        targs[i].target_hash = target_hash;
        targs[i].password_length = password_length;
        targs[i].thread_id = i;
        targs[i].total_threads = thread_count;
        targs[i].password_file = password_file;

        if (mode == 1) {
            pthread_create(&threads[i], NULL, thread_function_bruteforce, &targs[i]);
        } else if (mode == 2) {
            pthread_create(&threads[i], NULL, thread_function_file, &targs[i]);
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_join(stats_thread, NULL);

    if (!found) {
        printf(RED "\nPassword not found.\n" RESET);
    }

    return 0;
}
