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

enum{
	N=4096,
	K=512,
	HL=64,
};

char *begin="---BEGIN SRO SIGNATURE---\n";
char *end="---END SRO SIGNATURE---\n";

unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
				0x06, 0x09, 0x60, 0x86,
				0x48, 0x01, 0x65, 0x03,
				0x04, 0x02, 0x03, 0x05,
				0x00, 0x04, 0x40};

void writebase64(unsigned char *firma){
 BIO *bio;
 BIO *bio64;

 bio64 = BIO_new(BIO_f_base64());
 bio  = BIO_new_fp(stdout,BIO_NOCLOSE);
 BIO_push(bio64,bio);
 BIO_write(bio64,firma,K);
 BIO_flush(bio64);
 BIO_free_all(bio64);
}


unsigned char* padding(char* fichero){
  int archivo;
  int buffer_len=0;
  char buffer[64]="";
  unsigned char* hashtotal=malloc(K);
  unsigned char hash[SHA_DIGEST_LENGTH];
  unsigned char T[83];
  SHA512_CTX ctx;

  archivo=open(fichero,O_RDONLY);
  SHA512_Init(&ctx);
  while ((buffer_len= read(archivo,&buffer,64))>0){
    	SHA512_Update(&ctx, buffer,buffer_len);
  }
  SHA512_Update(&ctx, fichero, strlen(fichero));
  close(archivo);
  SHA512_Final(hash,&ctx);
  memcpy(T,EMSASHA512ID,sizeof(EMSASHA512ID));
  memcpy(T+19,hash,64);
  memset(hashtotal, 0, K);
  hashtotal[0]=0x00;
  hashtotal[1]=0x01;
  memset(hashtotal + 2,0xFF, 426);
  hashtotal[428]=0x00;
  memcpy(hashtotal + 429, T,sizeof(T));

  return hashtotal;
}

	int comprobarFirma(unsigned char *vfirma,int argc, char* argv[]){
		unsigned char* hashtotal=malloc(HL);
		hashtotal = padding(argv[3]);
			for(int x=0;x<K;x++){
				if(hashtotal[x]!=vfirma[x]){
					return 0;
				}
			}
		return 1;
	}

void readbase64(unsigned char *input, int length,int argc, char* argv[]) {
  BIO *b64, *bio;
  RSA *rsa;
  unsigned char hashFinal[K];
  char *buffer = (char *)malloc(length);

  memset(buffer, 0, length);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(input, length);
  bio = BIO_push(b64, bio);
  BIO_read(bio, buffer, length);
  BIO_free_all(bio);
  FILE* firmaPub=fopen(argv[4],"r");
  rsa=PEM_read_RSA_PUBKEY(firmaPub,NULL,NULL,NULL);
  RSA_public_decrypt(RSA_size(rsa),(unsigned char*)buffer,hashFinal,rsa,RSA_NO_PADDING);
  if (comprobarFirma(hashFinal,argc,argv)==0){
	printf("Firma incorrecta\n");
  }
}

void verificar(int argc, char* argv[]){
    char buffer[N]="";
    int archivo;
    int buffer_len;

    archivo=open(argv[2],O_RDONLY);
    buffer_len= read(archivo,buffer,N);
    readbase64((unsigned char*) buffer,buffer_len,argc,argv);
}

void firma(int argc, char* argv[]){
  unsigned char Final[N];
  unsigned char* hashtotal;
  RSA *privateKey = NULL;
  hashtotal = padding(argv[1]);
  FILE* fp=fopen(argv[2],"r");
  PEM_read_RSAPrivateKey(fp,&privateKey,NULL,NULL);
  RSA_private_encrypt(RSA_size(privateKey),hashtotal,Final,privateKey,RSA_NO_PADDING);
  printf("%s",begin);
  writebase64(Final);
  printf("%s",end);
}

int main(int argc, char* argv[]){
	if (argc>3){
		verificar(argc,argv);
	}else{
		firma(argc,argv);
	}
	exit(EXIT_SUCCESS);
}
