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
    size_t inblock_size = 16;
    unsigned char input[inblock_size];
    unsigned char hash_output[64];
    mbedtls_sha512_context ct;
    mbedtls_sha512_init( &ct );
    mbedtls_sha512_starts( &ct, 0 );

    if (!mode){



        for(int i = 0; inlen - i > inblock_size; i = i+inblock_size){
            infile.read((char*)input, inblock_size);
            mbedtls_sha512_update( &ct, input, inblock_size );

            //zasifrujem blok

            outfile.write((char*)input, inblock_size);
        }

        infile.read((char*)input, inlen % inblock_size);
        mbedtls_sha512_update( &ct, input, inlen % inblock_size );
        //padding a zasifrujem posledny blok
        outfile.write((char*)input, inlen % inblock_size);

        mbedtls_sha512_finish( &ct, hash_output );
        outfile.write((char*)hash_output, 64);

    }

    else{
        unsigned char given_hash[64];
        //dlzka viac ako 64

        for(int i = 0; (inlen-64) - i > inblock_size; i = i+inblock_size){
            infile.read((char*)input, inblock_size);
            //dešifrujem blok
            mbedtls_sha512_update( &ct, input, inblock_size );
        }

        infile.read((char*)input, (inlen-64) % inblock_size);
        //dešifrujem
        //outfile.write((char*)input, (inlen-64) % inblock_size);
        mbedtls_sha512_update( &ct, input, (inlen-64) % inblock_size );
        mbedtls_sha512_finish( &ct, hash_output );

        infile.read((char*)given_hash, 64);

        outfile.write((char*)given_hash, 64);
        outfile << endl;
        outfile.write((char*)hash_output, 64);


        for (size_t i = 0; i < 64; ++i){
        if (given_hash[i] != hash_output[i]){
            cerr << "Damaged message, hashes are not the same" << endl;
            break;
        }
        }


    }

    infile.close();
    outfile.close();
    mbedtls_sha512_free( &ct );

    cout << "Hello World!" << endl;
    return 0;
}

