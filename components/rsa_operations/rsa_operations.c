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
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
    }

    if ((ret = mbedtls_rsa_check_pubkey(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_check_pubkey returned %d\n\n", ret);
    }

    // unsigned char pubKeyPem[800];
    // size_t bufferSize = sizeof(pubKeyPem);
    // get_public_key(&rsa, pubKeyPem, bufferSize);
    // printf("Public key:\n%s", (char *)pubKeyPem);

    char *pubKeyPem = get_public_key_pem(&rsa);
    printf("Public key:\n%s", pubKeyPem);

    if ((ret = mbedtls_rsa_check_privkey(&rsa)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_check_privkey returned %d\n\n", ret);
    }

    save_pot_rsa_key_to_flash(&rsa);

    //print_private_key(&rsa);

    /////////////////////////////////////////////////////////
    // decrypt test

    // const char *message_hex = "c9777836649255f102c88e2c8a2cee78d328eace72b3e80b16060e7ae4c1a351acb635fd13aafc073920565c194ff48a5de838821fa6cca974bccf123ec05edffb11e2729d77cf233671873aafbfefffa97d14ac3487ab678ad037b889b1b4bd2fa9de08de00e0cdf7d91a5fc2ea8a3290bcc04403f7c919240ed78ad10064949b0ac62085629f224b9118cbe832344e0ae71876894db85c9cc6ecdc95520cdca3ad40079b17f493246d144fb40884fad0c7f31215ac8c430237fdadf6039b44b013887b820beeadd507840a5abc10fa0b3d6e2af56677f58b9a7056b10126e3b78e8478dda4b886d72668486ec225aff875b6b2864e2b071a44aef22f13cfd8";

    // // Konwertuj wiadomość z hex do binarnego
    // size_t message_size = strlen(message_hex) / 2;
    // unsigned char *message = (unsigned char *)malloc(message_size);
    // for (size_t i = 0; i < message_size; i++) {
    //     sscanf(message_hex + 2 * i, "%2hhx", &message[i]);
    // }

    // unsigned char decrypted[500]; //MBEDTLS_MPI_MAX_SIZE
    // size_t len_adr;
    // ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, &len_adr, message, decrypted, MBEDTLS_MPI_MAX_SIZE);
    // if (ret != 0) {
    //     mbedtls_printf("Decryption failed\n");
    // } else {
    //     mbedtls_printf("The decrypted result is: '%s'\n\n", decrypted);
    // }

    //////////////////////////////////////


    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    return pubKeyPem;
}

void encode_decode_test()
{
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);
    read_pot_rsa_key_from_flash(&rsa);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_context entropy;
    const char *pers = "rsa_genkey";
    mbedtls_entropy_init(&entropy);
    int ret = 1;
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    // encrypt
    // Encrypt using public key
    unsigned char input[] = "Hello, RSA!";
    printf("to encrypt: %s\n", input);
    unsigned char encrypted[512];
    printf("MBEDTLS_MPI_MAX_SIZE %d \n", MBEDTLS_MPI_MAX_SIZE);
    size_t encrypted_len = sizeof(input) - 1;
    int result;
    result = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, encrypted_len, input, encrypted);
    if (result != 0) {
        mbedtls_printf("Encryption failed\n");
    } else {
        mbedtls_printf("Encrypted data: ");
        for (size_t i = 0; i < rsa.MBEDTLS_PRIVATE(len); i++) {
        mbedtls_printf("%02X", encrypted[i]);
    }
        mbedtls_printf("\n");
    }

    // decrypt
    // unsigned char decrypted[512]; //MBEDTLS_MPI_MAX_SIZE
    // size_t len_adr;
    // result = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, &len_adr, encrypted, decrypted, MBEDTLS_MPI_MAX_SIZE);
    // if (result != 0) {
    //     mbedtls_printf("Decryption failed\n");
    // } else {
    //     mbedtls_printf("The decrypted result is: '%s'\n\n", decrypted);
    // }

    exit_code = MBEDTLS_EXIT_SUCCESS;

    mbedtls_rsa_free(&rsa);
}

void gen_key()
{
    // esp_vfs_spiffs_conf_t config = {
    //     .base_path = "/files",
    //     .partition_label = NULL,
    //     .max_files = 3,
    //     .format_if_mount_failed = true
    // };

    // esp_err_t result = esp_vfs_spiffs_register(&config);
    // if (result != ESP_OK){
    //     mbedtls_printf("Failed to initialize SPIFFS (%s)", esp_err_to_name(result));
    // }
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

    // if ((fpriv = fopen("/files/rsa_priv.txt", "r")) == NULL)
    // {
    //     mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for read\n");
    // }
    // else{
    //     char line[64];
    //     fgets(line, sizeof(line), fpriv);
    //     fclose(fpriv);
    //     printf("przed");
    //     printf("%s\n", line);
    //     printf("po");
    // }
    fclose(fpub);
    fclose(fpriv);
    mbedtls_printf(" ok\n\n");
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

void encode_rsa_by_pot_key()
{

    // esp_vfs_spiffs_conf_t config = {
    //     .base_path = "/files",
    //     .partition_label = NULL,
    //     .max_files = 3,
    //     .format_if_mount_failed = true
    // };

    // esp_err_t result = esp_vfs_spiffs_register(&config);
    // if (result != ESP_OK){
    //     mbedtls_printf("Failed to initialize SPIFFS (%s)", esp_err_to_name(result));
    // }

    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char buf[512];
    const char *pers = "rsa_encrypt";
    mbedtls_mpi N, E;

    mbedtls_printf("usage: rsa_encrypt <string of max 100 characters>\n");


    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&rsa);
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

    unsigned char input[] = "Hello, RSA!";
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
                                    &ctr_drbg, strlen((char *)input), input, buf);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                       ret);
        
    }

    printf("encrypted data: %s\n", buf);

    /*
     * Write the signature into result-enc.txt
     */
    // if ((f = fopen("result-enc.txt", "wb+")) == NULL)
    // {
    //     mbedtls_printf(" failed\n  ! Could not create %s\n\n", "result-enc.txt");
        
    // }

    // for (i = 0; i < rsa.MBEDTLS_PRIVATE(len); i++)
    // {
    //     mbedtls_fprintf(f, "%02X%s", buf[i],
    //                     (i + 1) % 16 == 0 ? "\r\n" : " ");
    // }

    // fclose(f);

    // mbedtls_printf("\n  . Done (created \"%s\")\n\n", "result-enc.txt");

    exit_code = MBEDTLS_EXIT_SUCCESS;

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);

    // mbedtls_exit(exit_code);
}

// void print_public_key(mbedtls_rsa_context *rsa) {
//     mbedtls_pk_context pk;
//     mbedtls_pk_init(&pk);
//     mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
//     mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);

//     printf( "Writing public key to string in PEM format)..\n" );
//     unsigned char pubKeyPem[500];
//     memset(pubKeyPem, 0, sizeof(pubKeyPem));
//     mbedtls_pk_write_pubkey_pem(&pk, pubKeyPem, sizeof(pubKeyPem));
//     printf("Public key:\n%s", (char*)pubKeyPem);
// }

// void print_private_key(mbedtls_rsa_context *rsa) {
//     mbedtls_pk_context pk;
//     mbedtls_pk_init(&pk);
//     mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
//     mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);

//     printf( "Writing private key to a PKCS#1 string)...\n" );
//     unsigned char privKeyPem[500];
//     memset(privKeyPem, 0, sizeof(privKeyPem));
//     // output_size = mbedtls_pk_write_key_der(&pk, NULL, 0);
//     // output_buffer = (unsigned char *)malloc(output_size);
//     mbedtls_pk_write_key_pem(&pk, privKeyPem, sizeof(privKeyPem));
//     // printf("Private key:%s", (char*)privKeyPem);
// }

// void print_private_key(mbedtls_rsa_context *rsa)
// {
//     size_t output_size;
//     unsigned char *output_buffer;

//     mbedtls_pk_context pk;
//     mbedtls_pk_init(&pk);
//     mbedtls_pk_rsa(pk) = rsa;

//     output_size = mbedtls_pk_write_key_der(&pk, NULL, 0);
//     output_buffer = (unsigned char *)malloc(output_size);
//     mbedtls_pk_write_key_pem (const mbedtls_pk_context *ctx, unsigned char *buf, size_t size)

//     char *key_str = (char *)malloc(2 * output_size + 1);
//     mbedtls_platform_bytes_to_hex(output_buffer, output_size, key_str, 2 * output_size + 1);

//     mbedtls_printf("Private Key:\n%s\n", key_str);

//     free(output_buffer);
//     free(key_str);
// }

// void get_public_key(mbedtls_rsa_context *rsa, unsigned char *pubKeyPemBuffer, size_t bufferSize) {
//     mbedtls_pk_context pk;
//     mbedtls_pk_init(&pk);
//     mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
//     mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);

//     printf("Writing public key to string in PEM format)..\n");
//     memset(pubKeyPemBuffer, 0, bufferSize);
//     mbedtls_pk_write_pubkey_pem(&pk, pubKeyPemBuffer, bufferSize);
// }