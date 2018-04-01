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
    long length = 16;
    long size = 2;
    /*unsigned char* in = read_file("datos.txt", &length);*/
    
    unsigned char out[length];
    std::vector<std::array<unsigned char, 16>> ciphers(size);
    unsigned char in[16] = {0x30, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char ivec[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char nonce[4] = {0x80, 0x00, 0x00, 0x00};
    const char key0[176] = "";
    const char key1[176] = "";
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
    /*for (long i = 0; i < size; i++) {*/
        //AES128_enc(in, out, length, key0, userkey0, number_of_rounds);
        //std::copy(out, out + 16, ciphers[i].begin());
		//printf("Cifra %d\n", i);
		//printhex(ciphers[i].data(), 16);
    /*}*/
}

