#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


//gcc -o hmacsha1 -Wall hmacsha1.c -lssl -lcrypto

enum{
	Ksz = 64,
	hashsz= 20,
	N=4096,
};


void first_hash(int argc, char* argv[],unsigned char k_ipad[],unsigned char hash[]){
	int archivo;  
	char buffer[N]="";

	SHA_CTX ctx;
	int buffer_len=0;

	archivo=open(argv[1],O_RDONLY);	
	SHA1_Init(&ctx);
   	SHA1_Update(&ctx, k_ipad, Ksz);	
	while ((buffer_len= read(archivo,&buffer,N))>0){
    		SHA1_Update(&ctx, buffer,buffer_len);
	}
	
   	close(archivo);
	SHA1_Final(hash,&ctx);
}

void second_hash(unsigned char k_opad[],unsigned char hash[]){
	SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, k_opad, Ksz); 
    SHA1_Update(&ctx, hash, hashsz); 
    SHA1_Final(hash, &ctx);
}

void hmac(int argc, char* argv[],unsigned char hash[]){
	int archivo, key_len; 
	unsigned char key[Ksz]= "";
	unsigned char k_ipad[Ksz];    
	unsigned char k_opad[Ksz];

	archivo=open(argv[2],O_RDONLY);
    key_len=read(archivo,key,Ksz);
	close(archivo);

	memset(k_ipad,0, Ksz);
   	memset(k_opad,0, Ksz);
 	memcpy(k_ipad,key,key_len);
    	memcpy(k_opad,key,key_len);

 	for (int i=0; i<Ksz; i++) {
       	 k_ipad[i] ^= 0x36;
       	 k_opad[i] ^= 0x5c;
    }

	first_hash(argc,argv,k_ipad,hash);  
	second_hash(k_opad,hash);
}

int main(int argc, char* argv[]){
	unsigned char hash[SHA_DIGEST_LENGTH];

	hmac(argc,argv,hash);
	for(int x=0;x<SHA_DIGEST_LENGTH;x++){
		printf("%02x",hash[x]);
	}	
	printf("\n");
	exit(EXIT_SUCCESS);
}
