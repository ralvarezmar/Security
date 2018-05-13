#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


//gcc -o hash64 -Wall hash64.c -lssl -lcrypto

enum{
	Ksz = 32,
	hashsz= 32,
	N=1000,
};


void first_hash(char* argumento,unsigned char hash[]){

	SHA256_CTX ctx;

	SHA256_Init(&ctx);
  SHA256_Update(&ctx, argumento,strlen(argumento));
	SHA256_Final(hash,&ctx);
}


void writebase64(unsigned char *firma){
 BIO *bio;
 BIO *bio64;

 bio64 = BIO_new(BIO_f_base64());
 bio  = BIO_new_fp(stdout,BIO_NOCLOSE);
 BIO_push(bio64,bio);
 BIO_write(bio64,firma,Ksz);
 BIO_flush(bio64);
 BIO_free_all(bio64);
}

int main(int argc, char* argv[]){
	unsigned char hash[SHA_DIGEST_LENGTH];

	first_hash(argv[1],hash);
  writebase64(hash);

	exit(EXIT_SUCCESS);
}
