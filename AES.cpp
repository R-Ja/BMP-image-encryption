#include <iostream>
#include <iomanip>
#include <fstream>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

int main(int argc, char* argv[]) {

    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    //bit). This key is secretly exchanged between two parties before communication   
    //begins. DEFAULT_KEYLENGTH= 16 bytes

    // key[ key length = 16(bytes) ], iv[ block size = 16(bytes) ]
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    //sets the values of key & iv in the memory to a 00000000
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //read a key from the user
    std::string keystring= "";
    std::cout<< "Please enter the key/ it should be 16 bytes long(16 characters or less, any extras will be ignored): ";
    std::cin>> keystring;
    if(keystring.length() < 17){
        for(uint8_t k= 0; k < keystring.length(); k++){
            key[k]= keystring[k];
        }
    }else{
        for(uint8_t k= 0; k < 16; k++){
            key[k]= keystring[k];
        }
    }

    //
    // String and Sink setup
    //
    std::string plaintext= "";//the image pixels
    std::string imagestring= "";//the image in binary
    std::string imageheader= "";//the image header in binary

    //---Read Image---
    std::ifstream image;
    image.open("image.bmp");
    if ( ! image ) {
        std::cout << "There is no input file.\n";
        exit(1);
    }else{
        while(image){//inputing the plain from a file
            std::string line; getline(image, line);
            imagestring+=line+'\n'; //it's a binary file not a text file
        }
        imagestring = imagestring.substr(0, imagestring.size()-2); //there are 2 extra newlines(\n)
    }
    image.close();
    

    int imagesize= imagestring.size();//file size
    int i; //index

    //check if this is a BMP image
    if(!(imagestring[0] == 'B' && imagestring[1] == 'M')){
        std::cout<<"This file is not of the format BMP"<<std::endl;
        exit(1);
    }

    i = (0xff & static_cast<byte>(imagestring[10])) +             // i is set to 
     (0xff & static_cast<byte>(imagestring[11]))* 256 +           // the value at
      (0xff & static_cast<byte>(imagestring[12]))* 256* 256 +     // which the 
       (0xff & static_cast<byte>(imagestring[13]))* 256* 256* 256;// pixels start
    //                                                            // in the file

    //read header / the values from the start until the pixels are reached
    for(int j= 0; j < i; j++){
        imageheader+= imagestring[j];
    }

    //read pixels
    for(i; i < imagesize; i++){
        plaintext+= imagestring[i];
    }
    //---Read Image---
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Create Cipher Text
    //
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    //
    // create an encrypted image
    //
    std::ofstream encimage ("EncryptedImage.bmp");

    encimage << imageheader << ciphertext;

    encimage.close();

    //
    // Decrypt
    //
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

    //
    // Create a Decrypted image
    //
    std::ofstream decimage ("DecryptedImage.bmp");

    decimage << imageheader << decryptedtext;

    decimage.close();

    return 0;
}