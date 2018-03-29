#ifndef RW_H
#define RW_H

#include <stdio.h>
#include <stdlib.h>

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

#endif // RW_H
