#include <iostream>
#include <unordered_map>
#include "aesni.h"
#include "util.h"

using std::cout;
using std::binary_search;
using std::lower_bound;
using std::endl;
using std::sort;
using std::unordered_map;

#define AES128_ROUNDS 10
#define AES256_ROUNDS 16

typedef std::pair<std::array<unsigned char, 16>, std::array<unsigned char, 16>> cypherKeyPair;
typedef std::unordered_map<std::array<unsigned char, 16>, std::array<unsigned char, 16>> cypherKeyMap;
struct ArrayHasher {
    std::size_t operator()(const std::array<unsigned char, 16>& a) const {
        std::size_t h = 0;

        for (auto e : a) {
            h ^= std::hash<unsigned char>{}(e)  + 0x9e3779b9 + (h << 6) + (h >> 2); 
        }
        return h;
    }   
};

void printTable(const unordered_map<array<unsigned char, 16>, array<unsigned char, 16>, ArrayHasher>& table)
{
    // Print data in table
    cout << "\nData in table" << endl;

    for(auto& p: table)
    {
        cout << "Cipher = ";
        printhex(p.first.data(), 16);
        cout << ", Key = ";
        printhex(p.second.data(), 16);
        printf("\n");
    }
}

int main()
{
    unsigned long length = 3;
    unsigned long size = 8;
    unsigned int number_of_rounds = AES128_ROUNDS;

    char key0[176] = "";
    char key1[176] = "";
    unsigned char userkey0[16] = "";
    unsigned char userkey1[16] = "";
    array<unsigned char, 16> mask = {};
    array<unsigned char, 16> arrkey0;
    array<unsigned char, 16> arrkey1;
    std::array<unsigned char, 16> cipher;
    std::vector<cypherKeyPair> keyciphers(size);
    std::vector<cypherKeyPair> keyciphers2(size);
    /*unsigned char* in = read_file("datos.txt", &length);*/
    unsigned char in[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char out[16] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char B[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char C[16] = "";
    /*unsigned char ivec[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};*/
    //unsigned char iv[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    /*unsigned char nonce[4] = {0x80, 0x00, 0x00, 0x00};*/

    /******** Operand modes *********/
    AES_ECB_encrypt(in, out, length, key0, number_of_rounds);
    //AES_CBC_encrypt(in, out, ivec, length, key0, number_of_rounds);
    /*AES_CFB_encrypt(in, out, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(in, out, iv, nonce, length, key, number_of_rounds);*/

    AES_ECB_decrypt(out, out, length, key1, number_of_rounds);
    //AES_CBC_decrypt(out, out, ivec, length, key0, number_of_rounds);
    /*AES_CFB_decrypt(out, m, ivec, length, key, number_of_rounds);*/
    /*AES_CTR_encrypt(out, m, iv, nonce, length, key, number_of_rounds);*/

    /******** Problem 1 *********/
    random_keygen(userkey0, userkey1);
    double_AES_enc(B, C, length, key0, key1, userkey0, userkey1, number_of_rounds);
    /*printf("C:\n");*/
    /*printhex(out, length);*/
    /*printf("\n");*/
    double_AES_dec(C, out, length, key0, key1, userkey0, userkey1, number_of_rounds);
    /*printf("M:\n");*/
    /*printhex(out, length);*/
    /*printf("\n");*/
    write_file("output.txt", out, length);

    /******** Problem 2 *********/
    generateMask(mask, length);
    /*********** A **************/
    /*std::cout << "K1:" << std::endl;*/
    /*printhex(userkey1, 16);*/
    copy(userkey1, userkey1 + 16, arrkey1.begin());
    for (unsigned long i = 0; i < size; i++) {
        truncateKey(arrkey1, mask, i);
        AES128_dec(C, out, length, key1, arrkey1.data(), number_of_rounds);
        std::copy(out, out + 16, keyciphers[i].first.begin());
        keyciphers[i].second = arrkey1;
    }

    // cout << "Before: " << endl;
    // for (long i = 0; i < size; i++)
    // {
    //     printf("Cifra %ld\n", i);
    //     printhex(keyciphers[i].first.data(), 16);
    //     printf(" ");
    //     printhex(keyciphers[i].second.data(), 16);
    //     printf("\n");
    // }

    sort(begin(keyciphers), end(keyciphers), [](const cypherKeyPair& lhs, const cypherKeyPair& rhs) -> bool
                         {
                            std::string a((const char*)lhs.first.data(), 16);
                            std::string b((const char*)rhs.first.data(), 16);

                            return a < b;
                         });

    /*cout << "\nSorted K1 table: " << endl;*/
    //for (unsigned long i = 0; i < size; i++)
    //{
        //printf("Cifra %ld\n", i);
        //printhex(keyciphers[i].first.data(), 16);
        //printf(" ");
        //printhex(keyciphers[i].second.data(), 16);
        //printf("\n");
    /*}*/

    copy(userkey0, userkey0 + 16, arrkey0.begin());

    for(unsigned long i = 0; i < size; i++)
    {
        truncateKey(arrkey0, mask, i);
        AES128_enc(B, out, length, key0, arrkey0.data(), number_of_rounds);
        /*std::copy(out, out + 16, keyciphers2[i].first.begin());*/
        /*keyciphers2[i].second = arrkey0;*/
        std::copy(out, out + 16, cipher.begin());

        auto p = make_pair(cipher, keyciphers[0].second);
        /*cout << "\nCipher requested: " << endl;*/
        //printhex(p.first.data(), 16);

        auto q = lower_bound(begin(keyciphers), end(keyciphers), p, [](const cypherKeyPair& lhs, const cypherKeyPair& rhs) -> bool
                         {
                            std::string a((const char*)lhs.first.data(), 16);
                            std::string b((const char*)rhs.first.data(), 16);

                            return a < b;
                         });

        std::string a((const char*)p.first.data(), 16);
        std::string b((const char*)(*q).first.data(), 16);

        if(q != keyciphers.end() && !(a < b))
        {
            cout << "Cipher found:" << endl;
            printhex((*q).first.data(), 16);
            cout << "\nKey1 found is: " << endl;
            printhex((*q).second.data(), 16);
            cout << "\nKey0 used is: " << endl;
            printhex(arrkey0.data(), 16);
            break;
        }
    }

    /*std::cout << "\n\nK0:" << std::endl;*/
    //printhex(userkey0, 16);
    //cout << "\nSorted K0 table: " << endl;
    //for (unsigned long i = 0; i < size; i++)
    //{
        //printf("Cifra %ld\n", i);
        //printhex(keyciphers2[i].first.data(), 16);
        //printf(" ");
        //printhex(keyciphers2[i].second.data(), 16);
        //printf("\n");
    //}*/
    /********** B ***********/
    unordered_map<array<unsigned char, 16>, array<unsigned char, 16>, ArrayHasher> cipherKeyTable;
 
    for(unsigned long i = 0; i < keyciphers.size(); i++)
    {
        cipherKeyTable.insert({keyciphers[i].first, keyciphers[i].second});
    }
 
    for(unsigned long i = 0; i < size; i++)
    {
        truncateKey(arrkey0, mask, i);
        AES128_enc(B, out, length, key0, arrkey0.data(), number_of_rounds);
        std::copy(out, out + 16, cipher.begin());
 
        auto p = cipherKeyTable.find(cipher);
 
        if(p != cipherKeyTable.end())
        {
            cout << "\nCipher found:" << endl;
            printhex((*p).first.data(), 16);
            cout << "\nKey1 found is: " << endl;
            printhex((*p).second.data(), 16);
            cout << "\nKey0 used is: " << endl;
            printhex(arrkey0.data(), 16);
            break;
        }
    }
    return 0;
}
