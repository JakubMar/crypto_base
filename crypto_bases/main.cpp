#include <iostream>
#include <cstring>
#include <fstream>
#include "mbedtls/aes.h"
using namespace std;

int main()
{
    mbedtls_aes_context aes;

    unsigned char key[32] =  { 0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11,
                               0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5 };

    unsigned char iv[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };

    //unsigned char input [128] = "abcdefgh ijklmno";
    //{0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    unsigned char output[128] = "";

    string name;
    cin >> name;
    ifstream infile (name);
    if (!infile){
        cerr << "Can not open file " << name << endl;
    }
    infile.seekg(0, infile.end);
    int inlen = infile.tellg();
    infile.seekg(0, infile.beg);
    unsigned char* input = new unsigned char[inlen];
    cout << inlen << endl;

   for(int i = 0; i < inlen; ++i){
            input[i] = infile.get();
            cout << input[i];
   }

    mbedtls_aes_setkey_enc( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, inlen, iv, input, output );


    ofstream outfile;
    outfile.open("encrypted.txt");
    outfile << output;
    outfile.close();
    delete input;


//decryption
    ifstream decfile ("encrypted.txt");
    /*unsigned char input2[128];
    char c;
    int i = 0;
    while (decfile.get(c)){
        input2[i] = c;
        cout << input2[i];
        ++i;
    }
    cout << i << endl;
*/

    if (!decfile){
        cerr << "Can not open file " << "encrypted.txt" << endl;
    }
    decfile.seekg(0, decfile.end);
    int declen = decfile.tellg();
    decfile.seekg(0, decfile.beg);
    unsigned char* dec_input = new unsigned char[declen];
    cout << declen << endl;

   for(int i = 0; i < declen; ++i){
            dec_input[i] = decfile.get();
            cout << dec_input[i];
   }
    //cout << input2 << endl;
    unsigned char  iv2[16] = { 0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d };
    mbedtls_aes_setkey_dec( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, declen, iv2, dec_input, output );
    cout << endl<<output << endl;


    cout << "Hello World!" << endl;
    return 0;
}

