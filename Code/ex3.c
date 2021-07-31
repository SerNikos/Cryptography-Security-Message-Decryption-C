//NIKOLAOS SERGIS PADA EX_3

#include <stdio.h> //basic library for input/output 
#include <openssl/bn.h> //library that helps the computer to deal with big numbers and not cause overflow
#define NBITS 128 //constant for bn, (in real life problems that number would be at least 512 bits)

//Function that prints a bn number
 void printBN(char *M, BIGNUM * a)
{

 /* Use BN_bn2hex(a) for hex string
 * Use BN_bn2dec(a) for decimal string */
 char * number_str = BN_bn2hex(a);
 printf("%s %s\n", M, number_str);
 OPENSSL_free(number_str);

}

int main ()
{
 BN_CTX *ctx = BN_CTX_new();//a temporary struct to help with the computational process of large numbers
 BIGNUM *n = BN_new(); //n will is the result of the multiplication of two first numbers p*q
 BIGNUM *d = BN_new(); //private key
 BIGNUM *C = BN_new(); //the decryption of the message
 BIGNUM *M = BN_new(); //The message in ascii

//Initialize n, d and C,
 BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
 BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D"); 
 BN_hex2bn(&C, "B3AF0A70793BB53492B5311AED5EA843D94661924C97A446E9DD75846DF860DF"); 

//Decryption of the message
 BN_mod_exp(M, C, d, n, ctx);

//Prints the decrypted message in ascii
 printBN("The decrypted message is ", M);

 return 0;
}
