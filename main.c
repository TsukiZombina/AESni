#include <time.h>
#include "aesni.h"
#include "rw.h"

int main()
{
    long length = 16;
    unsigned char* in = read_file("datos.txt", &length);

    time_t t;
    unsigned char out[length];
    /*unsigned char in[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};*/
    unsigned char ivec[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char nonce[4] = {0x80, 0x00, 0x00, 0x00};
    const char key0[176] = "";
    const char key1[176] = "";
    const unsigned char userkey0[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const unsigned char userkey1[16] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned int number_of_rounds = 10;
    unsigned char m[length];

    srand((unsigned) time(&t));

    AES_128_Key_Expansion(userkey0, (unsigned char*)key0);
    AES_128_Key_Expansion(userkey1, (unsigned char*)key1);
    
    printf("M:\n");
    printhex(in, length);
    AES_ECB_encrypt(in, out, length, key0, number_of_rounds);
    printf("C0:\n");
    printhex(out, length); 
    AES_ECB_encrypt(out, out, length, key1, number_of_rounds);
    /*AES_CBC_encrypt(in, out, ivec, length, key, number_of_rounds);*/
    /*AES_CFB_encrypt(in, out, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(in, out, iv, nonce, length, key, number_of_rounds);*/
    printf("C:\n");
    printhex(out, length); 

    AES_ECB_decrypt(out, m, length, key1, number_of_rounds);
    printf("C0':\n");
    printhex(m, length); 
    AES_ECB_decrypt(m, m, length, key0, number_of_rounds);
    /*AES_CBC_decrypt(out, m, ivec, length, key, number_of_rounds);*/
    /*AES_CFB_decrypt(out, m, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(out, m, iv, nonce, length, key, number_of_rounds);*/
    write_file("output.txt", m, length);
    printf("M:\n");
    printhex(m, length); 

    return 0;
}
