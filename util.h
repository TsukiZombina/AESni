#ifndef UTIL_H
#define UTIL_H

#include <array>
#include <time.h>
#include <cstdio>
#include <vector>
#include <utility>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <wmmintrin.h>

using std::vector;
using std::array;
using std::copy;

void print128_num(__m128i var) 
{
    int64_t *v64val = (int64_t*) &var;
    printf("%.16lx%.16lx\n", v64val[0], v64val[1]);
}

void printhex(const unsigned char *out, long length) {
    for(long i = 0; i < length; i++)
    {
        printf("%02x", out[i]);
    }
}

unsigned char* read_file(const char* filename, long* size)
{
    FILE* inputStream = fopen(filename, "r");
    if(!inputStream)
    {
        printf("Cannot open file");
        exit(1);
    }
    fseek(inputStream, 0, SEEK_END);
    *size = ftell(inputStream);
    unsigned char* data = (unsigned char*)malloc(sizeof(unsigned char) * *size);
    fseek(inputStream, 0, SEEK_SET);
    fread(data, sizeof(unsigned char), *size, inputStream);
    fclose(inputStream);
return data;
}

void write_file(const char* filename, unsigned char* data, long size)
{
    FILE* outputStream = fopen(filename, "w");
    if(!outputStream)
    {
        printf("Cannot open file");
        exit(1);
    }
    fwrite(data, sizeof(unsigned char), size, outputStream);
    fclose(outputStream);
}

void random_keygen(unsigned char* userkey0, unsigned char* userkey1) {
    time_t t;
    srand((unsigned) time(&t));

    for (long i = 0; i < 16; i++) {
        userkey0[i] = rand() % 0x100;
        userkey1[i] = rand() % 0x100;
    }
}

void generateMask(array<unsigned char, 16>& mask, unsigned long m)
{
    unsigned long p = m / 8;
    unsigned long q = m % 8;

    // Set mask
    for(unsigned long i = 0; i < 16; i++)
    {
        if(i < 16 - p)
        {
            mask[i] = 0xFF;
        }

        if(i == 16 - p - 1)
        {
            mask[i] = 255 << q;
        }
    }
}

void truncateKey(array<unsigned char, 16>& key, const array<unsigned char, 16>& mask, unsigned long index)
{
    for(unsigned long i = 0; i < 16; i++)
    {
        key[i] = key[i] & mask[i];
    }

    unsigned char* bits = (unsigned char*)&index;

    for(unsigned long i = 0; i < 4; i++)
    {
        key[15 - i] = key[15 -i] | *(bits + i);
        //printf("%02x", *(bits + i));
    }
}

bool sortByCipher(const std::pair<array<unsigned char, 16>, array<unsigned char, 16>> &a,
              const std::pair<array<unsigned char, 16>, array<unsigned char, 16>> &b)
{
    for(unsigned long i = 0; i < a.first.size(); i++) {
        if (a.first[i] != b.first[i]) {
            return true;
            break;
        }
    }
    return false;
}
#endif // UTIL_H
