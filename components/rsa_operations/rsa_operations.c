#include "rsa_operations.h"
#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include <stdio.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

extern void save_pot_rsa_key_to_flash(mbedtls_rsa_context *rsa);
extern void read_pot_rsa_key_from_flash(mbedtls_rsa_context *rsa);

int hex_to_bytes(const char *hex_string, unsigned char **bytes, size_t *length) {
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0) {
        // Nieparzysta liczba cyfr w reprezentacji heksadecymalnej
        return -1;
    }

    *length = hex_len / 2;
    *bytes = (unsigned char *)malloc(*length);
    if (*bytes == NULL) {
        // Błąd alokacji pamięci
        return -2;
    }

    for (size_t i = 0; i < *length; ++i) {
        int result = sscanf(hex_string + 2 * i, "%2hhx", (*bytes) + i);
        if (result != 1) {
            // Błąd konwersji
            fprintf(stderr, "Błąd konwersji dla indeksu %zu: %s\n", i, hex_string + 2 * i);
            free(*bytes);
            return -3;
        } else {
            fprintf(stderr, "Indeks %zu ok: %02x\n", i, (*bytes)[i]);
        }
    }

    return 0;
}

void string_to_hex(const char* input, size_t input_size, char* output) {
    //size_t input_length = input_size;

    // printf("Zakodowany tekst (for w string_to_hex): ");
    // for (size_t i = 0; i < input_size; ++i) {
    //     printf("%02x", output[i]);
    // }
    // printf("\n");

    if (2 * input_size > 512) {
        fprintf(stderr, "Zbyt długi ciąg do konwersji\n");
        return;
    }

    for (size_t i = 0; i < input_size; ++i) {
        sprintf(output + (i * 2), "%02x", (unsigned char)input[i]);
    }
}

void read_file(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Błąd otwierania pliku %s do odczytu\n", file_path);
        return;
    }

    char buffer[800];  // Maksymalnie 600 znaków plus jeden na znak końca ciągu
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';  // Dodaj znak końca ciągu
        printf("Zawartość pliku %s:\n%s", file_path, buffer);
    } else if (feof(file)) {
        fprintf(stderr, "Plik %s jest pusty\n", file_path);
    } else if (ferror(file)) {
        fprintf(stderr, "Błąd odczytu pliku %s\n", file_path);
    }

    fclose(file);
}


void save_pem_to_file(const char *pem_string) {
    const char *file_path = "/files/client_pub.txt";
    FILE *file = fopen(file_path, "wb");
    if (file == NULL) {
        fprintf("Błąd otwierania pliku %s do zapisu", file_path);
        return;
    }

    size_t pem_length = strlen(pem_string);
    size_t bytes_written = fwrite(pem_string, 1, pem_length, file);
    fclose(file);
    printf("Po zapisie");
}

void encrypt_by_s_key(char *hex_string, char *to_encrypt) {
    int ret = 1;
    const char *public_key_path = "/files/client_pub.txt";
    // unsigned char to_encrypt[14] = "zaszyfrowanko";

    // Inicjalizacja struktury klucza publicznego
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Odczyt klucza publicznego z pliku PEM
    FILE *key_file = fopen(public_key_path, "rb");
    if (key_file == NULL) {
        fprintf(stderr, "Błąd otwierania pliku %s\n", public_key_path);
        return;
    }
    else{
        printf("Plik %s otwarty\n", public_key_path);
    }

    if (mbedtls_pk_parse_public_keyfile(&pk, public_key_path) != 0) {
        fprintf(stderr, "Błąd parsowania klucza publicznego\n");
        fclose(key_file);
        mbedtls_pk_free(&pk);
        return;
    }
    else{
        printf("Sparsowano\n");
    }

    fclose(key_file);

    // Szyfrowanie
    size_t output_size = 0;
    unsigned char output[MBEDTLS_MPI_MAX_SIZE];

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    // Ustaw padding OAEP
    mbedtls_printf("\n  . Setting RSA padding to OAEP");
    ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_set_padding returned %d\n\n", ret);
    }

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }
    else{
        mbedtls_printf("Number generator ok\n");
    }

    if (mbedtls_pk_encrypt(&pk, (const unsigned char *)to_encrypt, strlen(to_encrypt),
                            output, &output_size, sizeof(output), mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        fprintf(stderr, "Błąd szyfrowania\n");
        mbedtls_pk_free(&pk);
        return;
    }
    else{
        printf("Zaszyfrowano\n");
    }

    // printf("Zakodowany tekst (for): ");
    // for (size_t i = 0; i < output_size; ++i) {
    //     printf("%02x", output[i]);
    // }
    // printf("\n");

    string_to_hex((const char*)output, output_size, hex_string);

    mbedtls_pk_free(&pk);
}


char *get_public_key_pem(mbedtls_rsa_context *rsa) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);

    printf("Writing public key to string in PEM format)..\n");
    size_t bufferSize = 800;
    char *pubKeyPem = (char *)malloc(bufferSize);
    if (pubKeyPem == NULL) {
        fprintf(stderr, "Failed to allocate memory for public key PEM.\n");
        exit(1); // lub obsługa błędu według potrzeb
    }

    memset(pubKeyPem, 0, bufferSize);
    mbedtls_pk_write_pubkey_pem(&pk, (unsigned char *)pubKeyPem, bufferSize);

    return pubKeyPem;
}

void *gen_rsa_keys_pair(){
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);
    // Ustaw padding OAEP
    mbedtls_printf("\n  . Setting RSA padding to OAEP");
    ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_set_padding returned %d\n\n", ret);
    }
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)) != 0)
    {
        mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
    }

    if ((fpub = fopen("/files/rsa_pub.txt", "wb+")) == NULL)
    {
        mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("/files/rsa_priv.txt", "wb+")) == NULL)
    {
        mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n\n");

    if(fpub != NULL) {
        fclose(fpub);
    }

    if(fpriv!= NULL) {
        fclose(fpriv);
    }

    char *pubKeyPem = get_public_key_pem(&rsa);
    printf("Public key:\n%s", pubKeyPem);

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return pubKeyPem;
}

void gen_key()
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);
    // Ustaw padding OAEP
    mbedtls_printf("\n  . Setting RSA padding to OAEP");
    ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_set_padding returned %d\n\n", ret);
    }
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)) != 0)
    {
        mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
    }

    if ((fpub = fopen("/files/rsa_pub.txt", "wb+")) == NULL)
    {
        mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("/files/rsa_priv.txt", "wb+")) == NULL)
    {
        mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
    }

    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret);
    }

    mbedtls_printf(" ok\n\n");

    if(fpub != NULL) {
        fclose(fpub);
    }

    if(fpriv!= NULL) {
        fclose(fpriv);
    }
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void encrypt_rsa_by_pot_key(unsigned char *input, size_t input_length, unsigned char *output, size_t *output_length)
{
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_encrypt";
    mbedtls_mpi N, E;

    mbedtls_printf("usage: rsa_encrypt <string of max 100 characters>\n");


    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&rsa);
    // Ustaw padding OAEP
    mbedtls_printf("\n  . Setting RSA padding to OAEP");
    ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_set_padding returned %d\n\n", ret);
    }
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
    }

    mbedtls_printf("\n  . Reading public key from rsa_pub.txt");
    fflush(stdout);

    if ((f = fopen("/files/rsa_pub.txt", "rb")) == NULL)
    {
        mbedtls_printf(" failed\n  ! Could not open rsa_pub.txt\n"
                       "  ! Please run rsa_genkey first\n\n");
        
    }

    if ((ret = mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&E, 16, f)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                       ret);
        fclose(f);
        
    }
    fclose(f);

    if ((ret = mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
        
    }
    printf("to encrypt: %s\n", input);
    if (strlen((char *)input) > 100)
    {
        mbedtls_printf(" Input data larger than 100 characters.\n\n");
        
    }

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf("\n  . Generating the RSA encrypted value");
    fflush(stdout);

    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random,
                                    &ctr_drbg, input_length, input, output);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                       ret);   
    }
    *output_length = mbedtls_rsa_get_len(&rsa);

    mbedtls_printf("Encrypted data: ");

    for (size_t i = 0; i < rsa.MBEDTLS_PRIVATE(len); i++) {
        mbedtls_printf("%02X", output[i]);
    }

    mbedtls_printf("\n\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);;
}

void decrypt_rsa_by_pot_key(unsigned char *input, size_t input_length, unsigned char *output, size_t *output_length)
{
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_decrypt";

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_rsa_init(&rsa);
    // Ustaw padding OAEP
    mbedtls_printf("\n  . Setting RSA padding to OAEP");
    ret = mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_set_padding returned %d\n\n", ret);
    }
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
    }

    mbedtls_printf("\n  . Reading private key from rsa_priv.txt");
    fflush(stdout);

    if ((f = fopen("/files/rsa_priv.txt", "rb")) == NULL) {
        mbedtls_printf(" failed\n  ! Could not open rsa_priv.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
    }

    if ((ret = mbedtls_mpi_read_file(&N, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&E, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&D, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&P, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&Q, 16, f))  != 0 ||
        (ret = mbedtls_mpi_read_file(&DP, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&DQ, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&QP, 16, f)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                       ret);
    }

    if ((ret = mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_import returned %d\n\n",
                       ret);
    }

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                       ret);
    }

    /*
     * Decrypt the encrypted RSA data and print the output.
     */
    mbedtls_printf("\n  . Decrypting the encrypted data");
    fflush(stdout);

    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random,
                                    &ctr_drbg, input_length,
                                    input, output, MBEDTLS_MPI_MAX_SIZE);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                       ret);
    }
    *output_length = input_length;
    mbedtls_printf("\n  . OK\n\n");
    mbedtls_printf("The decrypted output is: '%s'\n\n", output);
    exit_code = MBEDTLS_EXIT_SUCCESS;
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
}