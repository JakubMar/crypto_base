#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <mbedtls/cipher_internal.h>
#include <mbedtls/sha512.h>
using namespace std;

int main(int argc, char* argv[])
{
    if(argc != 4){
        cerr << "Wrong number of parameters: <mode> <input_file> <output_file>" << endl;
        return 1;
    }
    istringstream ss(argv[1]);
    int mode;
    if (!(ss >> mode))
        cerr << "Invalid number " << argv[1] << '\n';

    if ((mode != 0 ) && (mode != 1)){
        cerr << "Wrong mode: 0 - encrypt, 1 - decrypt" << endl;
        return 2;
    }

    mbedtls_cipher_context_t ctx;
    unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11};

    ifstream infile (argv[2]);
    if(!infile){
        cerr << "Cant open file: "<< argv[2] << endl;
        return 3;
    }
    ofstream outfile(argv[3]);
    if(!outfile){
        cerr << "Cant open file: "<< argv[3] << endl;
        return 3;
    }

    infile.seekg(0, infile.end);
    size_t inlen = infile.tellg();
    infile.seekg(0, infile.beg);
    unsigned char* input = new unsigned char[inlen];
    unsigned char hash_output[64];

    if (!mode){


        infile.read((char*)input, inlen);
        mbedtls_sha512( input, inlen, hash_output, 0 );
        //cout.write((char*)hash_output, 64); ////////////////////


        outfile.write((char*)hash_output, 64);
        //zašifruje a pripojí
        outfile.write((char*)input, inlen);

    }

    else{
        unsigned char given_hash[64];
        infile.read((char*)given_hash, 64);
        infile.read((char*)input, inlen - 64);
        cout.write((char*)input, inlen-64);
        //dešifrujem input

        mbedtls_sha512(input, inlen-64, hash_output, 0);
        if (!strcmp((char*)given_hash, (char*)hash_output)){
            cerr << "fuck" << endl;
        }
       /* for(int i = 0; i < 64; ++i){
            if(given_hash[i] != hash_output[i]){
                cout << "nerovnaju sa" << endl;
                break;
            }

        }*/
        {
            cout.write((char*)given_hash, 64);
            cout << endl;
            cout.write((char*)hash_output, 64);

        }

        //ohash.write((char*)input, inlen);

    }

    delete[] input;
    infile.close();
    outfile.close();

/*
    mbedtls_cipher_init	(&ctx);
    mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
    mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);
    mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_ENCRYPT);
    mbedtls_cipher_crypt(&ctx, iv, 16, input, inlen, output, &olen);
*/

    cout << "Hello World!" << endl;
    return 0;
}

