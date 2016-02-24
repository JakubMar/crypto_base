#include <iostream>
#include <cstring>
#include <fstream>
#include "mbedtls/aes.h"
using namespace std;

int main()
{
    mbedtls_aes_context aes;
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11};
    unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };

    string name;
    cin >> name;
    ifstream infile (name);
    if (!infile){
        cerr << "Can not open file " << name << endl;
        return 1;
    }
    infile.seekg(0, infile.end);
    int file_len = infile.tellg();
    int inlen = file_len;
    unsigned char modulo = file_len % 16;
    if (modulo != 0){
        inlen = file_len + 16 - modulo;
    }
    infile.seekg(0, infile.beg);
    unsigned char* input = new unsigned char[inlen];
    unsigned char* output = new unsigned char[inlen+1];
    memset(output, 0, inlen+1);
   for(int i = 0; i < file_len; ++i){
            input[i] = infile.get();
   }
   for(int j = file_len; j < inlen; ++j){
        input[j]= 16-modulo+48;
   }
    mbedtls_aes_setkey_enc( &aes, key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, inlen, iv, input, output );
    ofstream outfile;
    outfile.open("encrypted.txt");
    outfile << output;
    outfile.close();
    delete input;
    memset(output, 0, inlen);

//decryption
    ifstream decfile ("encrypted.txt");
    if (!decfile){
        cerr << "Can not open file " << "encrypted.txt" << endl;
    }
    decfile.seekg(0, decfile.end);
    int declen = decfile.tellg();
    decfile.seekg(0, decfile.beg);
    unsigned char* dec_input = new unsigned char[declen];

   for(int i = 0; i < declen; ++i){
            dec_input[i] = decfile.get();
   }
    unsigned char  iv2[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    mbedtls_aes_setkey_dec( &aes, key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, declen, iv2, dec_input, output );
    ofstream final ("final.txt");
    final << output;

    delete output;
    cout << "Hello World!" << endl;
    return 0;
}

