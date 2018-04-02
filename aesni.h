#ifndef AESNI_H
#define AESNI_H

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#define cpuid(func,ax,bx,cx,dx)\
    __asm__ __volatile__ ("cpuid":\
    "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

__m128i AES_128_ASSIST(__m128i temp1, __m128i temp2);
void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2);
void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3);

int Check_CPU_support_AES()
{
    unsigned int a,b,c,d;
    cpuid(1, a,b,c,d);
    return (c & 0x2000000);
}

inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

/*inline void KEY_192_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3)*/
//{
    //__m128i temp4;
    //*temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
    //temp4 = _mm_slli_si128 (*temp1, 0x4);
    //*temp1 = _mm_xor_si128 (*temp1, temp4);
    //temp4 = _mm_slli_si128 (temp4, 0x4);
    //*temp1 = _mm_xor_si128 (*temp1, temp4);
    //temp4 = _mm_slli_si128 (temp4, 0x4);
    //*temp1 = _mm_xor_si128 (*temp1, temp4);
    //*temp1 = _mm_xor_si128 (*temp1, *temp2);
    //*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    //temp4 = _mm_slli_si128 (*temp3, 0x4);
    //*temp3 = _mm_xor_si128 (*temp3, temp4);
    //*temp3 = _mm_xor_si128 (*temp3, *temp2);
/*}*/

inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    *temp1 = _mm_xor_si128 (*temp1, *temp2);
}

inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3)
{
    __m128i temp2,temp4;
    temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    *temp3 = _mm_xor_si128 (*temp3, temp2);
}

void AES_128_Key_Expansion(const unsigned char *userkey,
                           unsigned char *key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;

    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

/*void AES_192_Key_Expansion(const unsigned char *userkey,*/
                            //unsigned char *key)
//{
    //__m128i temp1, temp2, temp3;
    //__m128i *Key_Schedule = (__m128i*)key;
    //temp1 = _mm_loadu_si128((__m128i*)userkey);
    //temp3 = _mm_loadu_si128((__m128i*)(userkey+16));
    //Key_Schedule[0]=temp1;
    //Key_Schedule[1]=temp3;
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x1);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1],
                                              //(__m128d)temp1,0);
    //Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x2);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[3]=temp1;
    //Key_Schedule[4]=temp3;
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x4);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4],
                                              //(__m128d)temp1,0);
    //Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x8);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[6]=temp1;
    //Key_Schedule[7]=temp3;
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x10);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7],
                                              //(__m128d)temp1,0);
    //Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x20);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[9]=temp1;
    //Key_Schedule[10]=temp3;
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x40);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10],
                                               //(__m128d)temp1,0);
    //Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    //temp2=_mm_aeskeygenassist_si128 (temp3,0x80);
    //KEY_192_ASSIST(&temp1, &temp2, &temp3);
    //Key_Schedule[12]=temp1;
/*}*/

void AES_256_Key_Expansion (const unsigned char *userkey,
                            unsigned char *key)
{
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    temp3 = _mm_loadu_si128((__m128i*)(userkey+16));
    Key_Schedule[0] = temp1;
    Key_Schedule[1] = temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[2]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[3]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[4]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[5]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[6]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[7]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[8]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[9]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[10]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[11]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[12]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[13]=temp3;
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[14]=temp1;
}

void AES_enc(const unsigned char* in,
             const char *key, //pointer to the expanded key schedule
             int number_of_rounds, //number of AES rounds 10,12 or 14
             unsigned char *out) //pointer to the CIPHERTEXT buffer

{
    __m128i tmp;
    int j;
    tmp = _mm_loadu_si128 (&((__m128i*)in)[0]);
    tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
    for(j = 1; j <number_of_rounds; j++){
        tmp = _mm_aesenc_si128 (tmp,((__m128i*)key)[j]);
    }
    tmp = _mm_aesenclast_si128 (tmp,((__m128i*)key)[j]);
    _mm_storeu_si128 ((__m128i*)out,tmp);
    /*return tmp;*/
}

__m128i AES_dec(const unsigned char* in,
             const char *key, //pointer to the expanded key schedule
             int number_of_rounds, //number of AES rounds 10,12 or 14
             unsigned char *out) //pointer to the CIPHERTEXT buffer
{
    __m128i tmp;
    int j;
    tmp = _mm_loadu_si128 (&((__m128i*)in)[0]);
    tmp = _mm_xor_si128 (tmp,((__m128i*)key)[10]);
    for(j = number_of_rounds - 1; j > 0; j--) {
        tmp = _mm_aesdec_si128 (tmp,_mm_aesimc_si128(((__m128i*)key)[j]));
    }
    tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)key)[j]);
    _mm_storeu_si128 ((__m128i*)out,tmp);
    //return tmp;
}

void AES_ECB_encrypt(const unsigned char *in, //pointer to the PLAINTEXT
                     unsigned char *out, //pointer to the CIPHERTEXT buffer
                     unsigned long length, //text length in bytes
                     const char *key, //pointer to the expanded key schedule
                     int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m128i tmp;
    unsigned int i;
    if(length%16)
        length = length/16+1;
    else
        length = length/16;
    for(i=0; i < length; i++){
        AES_enc(in + i * 16, key, number_of_rounds, out + i * 16);
        /*tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);*/
        /*tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);*/
        /*for(j=1; j <number_of_rounds; j++){*/
        /*tmp = _mm_aesenc_si128 (tmp,((__m128i*)key)[j]);*/
        /*}*/
        /*tmp = _mm_aesenclast_si128 (tmp,((__m128i*)key)[j]);*/
        /*_mm_storeu_si128 (&((__m128i*)out)[i],tmp);*/
    }
}

void AES_ECB_decrypt(const unsigned char *in, //pointer to the CIPHERTEXT
                     unsigned char *out, //pointer to the DECRYPTED TEXT buffer
                     unsigned long length, //text length in bytes
                     const char *key, //pointer to the expanded key schedule
                     int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m128i tmp;
    unsigned int i;
    if(length%16)
        length = length/16+1;
    else
        length = length/16;
    for(i=0; i < length; i++){
        AES_dec(in + i * 16, key, number_of_rounds, out + i * 16);
        /*tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);*/
        /*tmp = _mm_xor_si128 (tmp,((__m128i*)key)[10]);*/
        /*for(j=1; j <number_of_rounds; j++){*/
        /*tmp = _mm_aesdec_si128 (tmp,((__m128i*)key)[j]);*/
        /*}*/
        /*tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)key)[j]);*/
        //_mm_storeu_si128 (&((__m128i*)out)[i],tmp);
    }
}

void AES_CBC_encrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     unsigned int number_of_rounds)
{
    __m128i feedback,data;
    unsigned int i,j;
    if (length%16)
        length = length/16+1;
    else length /=16;
    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++){
        data = _mm_loadu_si128 (&((__m128i*)in)[i]);
        feedback = _mm_xor_si128 (data,feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)key)[0]);
        for(j=1; j < number_of_rounds; j++)
            feedback = _mm_aesenc_si128 (feedback,((__m128i*)key)[j]);
        feedback = _mm_aesenclast_si128 (feedback,((__m128i*)key)[j]);
        _mm_storeu_si128 (&((__m128i*)out)[i],feedback);
    }
}

void AES_CBC_decrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     unsigned int number_of_rounds)
{
    __m128i data,feedback,last_in;
    unsigned int i,j;
    if (length%16)
        length = length/16+1;
    else length /=16;
    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++){
        last_in=_mm_loadu_si128 (&((__m128i*)in)[i]);
        data = _mm_xor_si128 (last_in,((__m128i*)key)[10]);
        for(j=number_of_rounds - 1; j > 0; j--){
            data = _mm_aesdec_si128 (data,_mm_aesimc_si128(((__m128i*)key)[j]));
        }
        data = _mm_aesdeclast_si128 (data,((__m128i*)key)[j]);
        data = _mm_xor_si128 (data,feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i],data);
        feedback=last_in;
    }
}

void AES_CFB_encrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     unsigned int number_of_rounds)
{
    __m128i feedback,data;
    unsigned int i,j;
    if (length%16)
        length = length/16+1;
    else length /=16;
    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++){
        data = _mm_loadu_si128 (&((__m128i*)in)[i]);
        feedback = _mm_xor_si128 (feedback,((__m128i*)key)[0]);
        for(j=1; j < number_of_rounds; j++)
            feedback = _mm_aesenc_si128 (feedback,((__m128i*)key)[j]);
        feedback = _mm_aesenclast_si128 (feedback,((__m128i*)key)[j]);
        feedback = _mm_xor_si128(data, feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i],feedback);
    }
}

void AES_CFB_decrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     unsigned int number_of_rounds)
{
    __m128i feedback,data;
    unsigned int i,j;
    if (length%16)
        length = length/16+1;
    else length /=16;
    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++){
        data = _mm_loadu_si128 (&((__m128i*)in)[i]);
        feedback = _mm_xor_si128 (feedback,((__m128i*)key)[10]);
        for(j=number_of_rounds - 1; j > 0; j--)
            feedback = _mm_aesenc_si128 (feedback,_mm_aesimc_si128(((__m128i*)key)[j]));
        feedback = _mm_aesenclast_si128 (feedback,_mm_aesimc_si128(((__m128i*)key)[j]));
        feedback = _mm_xor_si128(data, feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i],feedback);
        feedback = data;
    }
}

void AES_CTR_encrypt (const unsigned char *in,
                      unsigned char *out,
                      const unsigned char ivec[8],
                      const unsigned char nonce[4],
                      unsigned long length,
                      const char *key,
                      unsigned int number_of_rounds)
{
    __m128i ctr_block, tmp, ONE, BSWAP_EPI64;
    unsigned int i,j;
    if (length%16)
        length = length/16 + 1;
    else length/=16;
    ONE = _mm_set_epi32(0,1,0,0);
    BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
    ctr_block = _mm_setzero_si128();
    ctr_block = _mm_insert_epi64(ctr_block, *(long long*)ivec, 1);
    ctr_block = _mm_insert_epi32(ctr_block, *(long*)nonce, 1);
    ctr_block = _mm_srli_si128(ctr_block, 4);
    ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    for(i=0; i < length; i++){
        tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
        ctr_block = _mm_add_epi64(ctr_block, ONE);
        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++) {
            tmp = _mm_aesenc_si128 (tmp, ((__m128i*)key)[j]);
        };
        tmp = _mm_aesenclast_si128 (tmp, ((__m128i*)key)[j]);
        tmp = _mm_xor_si128(tmp,_mm_loadu_si128(&((__m128i*)in)[i]));
        _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
    }
}

void double_AES_enc(const unsigned char* in,
        unsigned char* out, 
        unsigned long length, 
        const char* key0,
        const char* key1,
        const unsigned char* userkey0, 
        const unsigned char* userkey1,
        unsigned int number_of_rounds) 
{
    AES_128_Key_Expansion(userkey0, (unsigned char*)key0);
    AES_128_Key_Expansion(userkey1, (unsigned char*)key1);
    
    AES_ECB_encrypt(in, out, length, key0, number_of_rounds);
    /*printf("C0:\n");*/
    /*printhex(out, length); */
    AES_ECB_encrypt(out, out, length, key1, number_of_rounds);
}

void double_AES_dec(const unsigned char* in,
        unsigned char* out, 
        unsigned long length, 
        const char* key0,
        const char* key1,
        const unsigned char* userkey0, 
        const unsigned char* userkey1,
        unsigned int number_of_rounds) 
{
    AES_128_Key_Expansion(userkey0, (unsigned char*)key0);
    AES_128_Key_Expansion(userkey1, (unsigned char*)key1);
    
    AES_ECB_decrypt(in, out, length, key1, number_of_rounds);
    /*printf("\nC0':\n");*/
    /*printhex(out, length); */
    /*printf("\n");*/
    AES_ECB_decrypt(out, out, length, key0, number_of_rounds);
}

void AES128_enc(const unsigned char* in,
        unsigned char* out, 
        unsigned long length, 
        const char* key,
        const unsigned char* userkey, 
        unsigned int number_of_rounds) 
{
    AES_128_Key_Expansion(userkey, (unsigned char*)key);
    AES_ECB_encrypt(in, out, length, key, number_of_rounds);
}

void AES128_dec(const unsigned char* in,
        unsigned char* out, 
        unsigned long length, 
        const char* key,
        const unsigned char* userkey, 
        unsigned int number_of_rounds) 
{
    AES_128_Key_Expansion(userkey, (unsigned char*)key);
    AES_ECB_decrypt(in, out, length, key, number_of_rounds);
}

#endif // AESNI_H