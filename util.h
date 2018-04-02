#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <wmmintrin.h>
#include <cstdio>
#include <vector>
#include <array>
#include <algorithm>

using std::vector;
using std::array;
using std::copy;

void print128_num(__m128i var) 
{
    int64_t *v64val = (int64_t*) &var;
    printf("%.16lx%.16lx\n", v64val[0], v64val[1]);
}

void printhex(const unsigned char *out, long length) {
    for(int i = 0; i < length; i++)
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

    for (int i = 0; i < 16; i++) {
        userkey0[i] = rand() % 2;
        userkey1[i] = rand() % 2;
    }
}

void generateMask(array<unsigned char, 16>& mask, int m)
{
    unsigned int p = m / 8;
    unsigned int q = m % 8;

    // Set mask
    for(unsigned int i = 0; i < 16; i++)
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

void truncateKey(array<unsigned char, 16>& key, const array<unsigned char, 16>& mask, unsigned int index)
{
    for(unsigned int i = 0; i < 16; i++)
    {
        key[i] = key[i] & mask[i];
    }

    unsigned int p = index / 255;
    unsigned int q = index % 255;

    printf("\np = %d, q = %d\n", p, q);

    for(unsigned int i = 0; i < 16; i++)
    {
        if(i > 16 - p)
        {
            key[i] = 0xFF;
        }

        if(i == 16 - p - 1)
        {
            key[i] += q;
        }
    }
}

#endif // UTIL_H
