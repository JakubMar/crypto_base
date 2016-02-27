#include <iostream>
#include <fstream>
#include <sstream>
#include <mbedtls/aes.h>
#include <mbedtls/sha512.h>
using namespace std;

int main(int argc, char* argv[])
{
    /* parsing arguments */
    if(argc != 4){
        cerr << "Wrong number of parameters: <enc = 0 | dec = 1> <input_file> <output_file>" << endl;
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

    /* initialization */
    infile.seekg(0, infile.end);
    size_t inlen = infile.tellg();
    infile.seekg(0, infile.beg);
    mbedtls_aes_context ctx;
    unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    unsigned char key[16] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11};
    size_t inblock_size = 16;
    unsigned char input[inblock_size];
    unsigned char output[inblock_size];
    unsigned char hash_output[64];
    mbedtls_sha512_context ct;
    mbedtls_sha512_init( &ct );
    mbedtls_sha512_starts( &ct, 0 );
    mbedtls_aes_init( &ctx );

    /* encryption */
    if (!mode){
        mbedtls_aes_setkey_enc(&ctx, key, 128);

        for(int i = 0; inlen - i > inblock_size; i = i+inblock_size){
            infile.read((char*)input, inblock_size);
            mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, inblock_size, iv, input, output);
            outfile.write((char*)output, inblock_size);
            mbedtls_sha512_update( &ct, input, inblock_size );
        }

        infile.read((char*)input, inlen % inblock_size);
        for (size_t i = inlen % inblock_size; i < inblock_size; ++i){
            input[i] = inlen % inblock_size;
        }
        mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, inblock_size, iv, input, output);
        outfile.write((char*)output, inblock_size);
        mbedtls_sha512_update( &ct, input, inblock_size );
        mbedtls_sha512_finish( &ct, hash_output );
        outfile.write((char*)hash_output, 64);
    }

    /*decryption*/
    else{
        if ((inlen < 64) || (inlen % inblock_size != 0)){
            cerr << "not suitable length of input file" << endl;
            return 4;
        }
        mbedtls_aes_setkey_dec(&ctx, key, 128);

        for(int i = 0; inlen - i > 64; i = i+inblock_size){
            infile.read((char*)input, inblock_size);
            mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, inblock_size, iv, input, output);
            mbedtls_sha512_update( &ct, output, inblock_size );
            outfile.write((char*)output, inblock_size);
        }

        mbedtls_sha512_finish( &ct, hash_output );

        unsigned char given_hash[64];
        infile.read((char*)given_hash, 64);

        cout << "hash control: " <<endl;
        cout.write((char*)given_hash, 64);
        cout << endl;
        cout.write((char*)hash_output, 64);

        for (size_t i = 0; i < 64; ++i){
            if (given_hash[i] != hash_output[i]){
                cerr << "nok, damaged message" << endl;
                break;
            }
        }
        cout << "\nok" << endl;
    }

    infile.close();
    outfile.close();
    return 0;
}

