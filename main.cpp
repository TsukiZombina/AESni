#include <iostream>
#include <algorithm>
#include <vector>
#include <array>
#include "aesni.h"
#include "util.h"

#define AES128_ROUNDS 10
#define AES256_ROUNDS 16

int main()
{
    long length = 10;
    long size = 1024;
    /*unsigned char* in = read_file("datos.txt", &length);*/
    
    unsigned char out[length];
    std::vector<std::pair<std::array<unsigned char, 16>, std::array<unsigned char, 16>>> keyciphers(size);
    array<unsigned char, 16> mask = {};
    array<unsigned char, 16> arrkey1;
    unsigned char in[16] = {0x30, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char ivec[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char nonce[4] = {0x80, 0x00, 0x00, 0x00};
    char key0[176] = "";
    char key1[176] = "";
    unsigned char userkey0[16] = "";
    unsigned char userkey1[16] = "";
    unsigned int number_of_rounds = 10;

    /******** Operand modes *********/ 
    AES_ECB_encrypt(in, out, length, key0, number_of_rounds);
    //AES_CBC_encrypt(in, out, ivec, length, key0, number_of_rounds);
    /*AES_CFB_encrypt(in, out, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(in, out, iv, nonce, length, key, number_of_rounds);*/

    AES_ECB_decrypt(out, out, length, key1, number_of_rounds);
    //AES_CBC_decrypt(out, out, ivec, length, key0, number_of_rounds);
    /*AES_CFB_decrypt(out, m, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(out, m, iv, nonce, length, key, number_of_rounds);*/ 

    /******** Problema 1 *********/    
    random_keygen(userkey0, userkey1);
    double_AES_enc(in, out, length, key0, key1, userkey0, userkey1, number_of_rounds);
    /*printf("C:\n");*/
    /*printhex(out, length);*/
    /*printf("\n");*/
    double_AES_dec(out, out, length, key0, key1, userkey0, userkey1, number_of_rounds);
    /*printf("M:\n");*/
    /*printhex(out, length);*/
    /*printf("\n");*/
    write_file("output.txt", out, length);

    /******** Problema 2 *********/
    copy(userkey1, userkey1 + 16, arrkey1.begin());
    generateMask(mask, length);
    for (long i = 0; i < size; i++) {
        truncateKey(arrkey1, mask, i);
        AES128_enc(in, out, length, key1, arrkey1.data(), number_of_rounds);
        std::copy(out, out + 16, keyciphers[i].first.begin());
        keyciphers[i].second = arrkey1;
		// printf("Cifra %ld\n", i);
		// printhex(keyciphers[i].first.data(), 16);
        // printf(" ");
        // printhex(keyciphers[i].second.data(), 16);
        // printf("\n");
    }
}
