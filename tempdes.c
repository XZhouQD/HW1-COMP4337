/*
	AUTHOR:
		Ryan Ambrose (z5018097), Aaron Lai (z5075510)
	MODIFY DATE:
		2018-Apr-07
	DESCRIPTION:
		Homework 1 - cs4337 Securing Wireless Networks - S1, 2018
		Provided skeleton code we are to implement Cipher Block Chaining
		(CBC) using DES encryption imported from the OpenSSL library.
		The idea of CBC is that we use the ciphertext from the previous
		block to impact the next block.
		1. First the message is broken into identically sized blocks
		2. XOR the first block with the IV
		3. Encrypt it with our encryption function (DES, key reused)
		4. Transmit the cipher block text
		5. Repeat again, but replace the IV the previous cipher text
		   XOR(m,c-1), where c-1 is the previous bloc cipher text.
	NOTES:
		Skeleton code provided by cs3447
*/

#include <openssl/des.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>

#define ENC 1
#define DEC 0
#define MODE 0

#define BLOCK_BYTE_SIZE 8
#define IV_ARG 1
#define KEY_ARG 2
#define IN_FILE_ARG 3
#define OUT_FILE_ARG 4

int main(int argc, char **argv)
{
	//timing variables
	struct timeval st, et;
	
	unsigned char val2;
	
	//check number of provided arguments
	if (argc != 5) {
		printf("\nAn incorrect number of arguments has been entered. Please enter arguments as IV, KEY, INPUT, OUTPUT.\n");
		return 0;
	}
	//check for all hex characters in IV
	for (int i = 0; i < 16; i++) {
		
    	sscanf(argv[IV_ARG]+(i), "%c", &val2);
    	if (val2 != '0' && val2 != '1' && val2 != '2' && val2 != '3' && val2 != '4' && val2 != '5' && val2 != '6' && val2 != '7' && val2 != '8' && val2 != '9' && val2 != 'a' && val2 != 'b' && val2 != 'c' && val2 != 'd' && val2 != 'e' && val2 != 'f') {
    		printf("\nNon-hex character found in IV, aborting.\n");
			return 0;
		}
    }
    //check for all hex characters in key
    for (int i = 0; i < 16; i++) {
		
    	sscanf(argv[KEY_ARG]+(i), "%c", &val2);
    	if (val2 != '0' && val2 != '1' && val2 != '2' && val2 != '3' && val2 != '4' && val2 != '5' && val2 != '6' && val2 != '7' && val2 != '8' && val2 != '9' && val2 != 'a' && val2 != 'b' && val2 != 'c' && val2 != 'd' && val2 != 'e' && val2 != 'f') {
    		printf("\nNon-hex character found in key, aborting.\n");
			return 0;
		}
    }
	

	// 64-bit (8 byte) IV (Initialisation Vector)
	// 64-bit (8 byte) Key
	// Read both args as hexadecimal
	unsigned char IV[BLOCK_BYTE_SIZE];
	unsigned char cbc_key[BLOCK_BYTE_SIZE];
	for (int i = 0; i < BLOCK_BYTE_SIZE; i++) {
    	sscanf(argv[IV_ARG]+(2*i), "%2hhx", &IV[i]);
    	sscanf(argv[KEY_ARG]+(2*i), "%2hhx", &cbc_key[i]);
    }
	printf("IV: ");
	for (int i = 0; i < BLOCK_BYTE_SIZE; i++) {
		printf("%x",IV[i]);
	}
	printf("\n");
	printf("KEY: ");
	for (int i = 0; i < BLOCK_BYTE_SIZE; i++) {
		printf("%x",cbc_key[i]);
	}
	printf("\n");
	
	//test key and IV length
	if (strlen(argv[KEY_ARG]) != 16) {
		printf("\nThe provided key was not the correct length. Aborting operation.\n");
		return 0;
	}
	if (strlen(argv[IV_ARG]) != 16) {
		printf("\nThe provided IV was not the correct length. Aborting operation.\n");
		return 0;
	}
	

	// Open the file
	FILE * inFile = fopen(argv[IN_FILE_ARG], "r");
	//check file validity
	if (inFile == NULL) {
		printf("\nThe input file could not be found, or could not be opened. Aborting oepration.\n");
		return 0;
	}
	// Seek to the end to get the file size
	fseek(inFile, 0, SEEK_END);
	int inFileSize = ftell(inFile);
	printf("inFileSize: %d\n",inFileSize);
	// Pad the file size to the nearest block
	int inFileSizePadded = (int)ceil((double)inFileSize/(double)BLOCK_BYTE_SIZE)*BLOCK_BYTE_SIZE;
	// Read the file into a buffer
	fseek(inFile,0,SEEK_SET);
	unsigned char inBuff[inFileSizePadded];
	memset(inBuff,0x00,inFileSizePadded);
	for(int i = 0; i < inFileSize; i++) {
          fscanf(inFile, "%c", &inBuff[i]);
    }
    fclose(inFile); 

    // Initialise out buffer
    unsigned char outBuff[inFileSizePadded];
	memset(outBuff,0x00,inFileSizePadded);
	printf("outBuff Size: %lu\n", sizeof(outBuff));
    // CBC is Encrypt(XOR(m,c-1))
    unsigned char XOR[BLOCK_BYTE_SIZE];
    unsigned char plainBlock[BLOCK_BYTE_SIZE];
    unsigned char XORBlock[BLOCK_BYTE_SIZE];
    unsigned char encryptBlock[BLOCK_BYTE_SIZE];
    

	// Before a DES key can be used, it must be converted
	// into the architecture dependent DES_key_schedule
	des_key_schedule key;
	int dskc = des_set_key_checked(&cbc_key,key);
	// Create the DES key by passing the current CBC Key
	if (dskc != 0) {
		if (dskc == -1) {
			printf("\nThe provided key did not have odd parity. Aborting operation.\n");
			return 0;
		} else if (dskc == -2) {
			printf("\nThe provided key was too weak. Aborting operation.\n");
			return 0;
		} else {
			printf("\nThere was an error in checking the key. Aborting operation.\n");
			return 0;
		}	
	}

    // First iteration, the IV is used to XOR
    memcpy(XOR,IV,BLOCK_BYTE_SIZE);
    
    if (MODE == 1) {
		
		//pick timing initiation just before the cipher
		gettimeofday(&st, NULL);
		
		//encryption version
		for (int i = 0; i < inFileSizePadded; i += BLOCK_BYTE_SIZE) {
			// Read the first BLOCK_BYTE_SIZE bytes from the in file
			memcpy(plainBlock,&inBuff[i],BLOCK_BYTE_SIZE);
			// XOR them with the previous output cipher text (or IV)
			for (int j = 0; j < BLOCK_BYTE_SIZE; j++) {
				XORBlock[j] = plainBlock[j]^XOR[j];
			}
			// Encrypt the message block
			memcpy(encryptBlock,XORBlock,BLOCK_BYTE_SIZE);
			des_encrypt1((long unsigned int *)encryptBlock,key,ENC);
			// Write to out buffer
			memcpy(&outBuff[i],encryptBlock,BLOCK_BYTE_SIZE);
			// Update the cbc_key
			memcpy(XOR,encryptBlock,BLOCK_BYTE_SIZE);
		}
		
		//pick timing conclusion right after the cipher
		gettimeofday(&et, NULL);
		
    } else {
		
		//pick timing initiation just before the cipher
		gettimeofday(&st, NULL);
		
		//decryption version
		for (int i = 0; i < inFileSizePadded; i += BLOCK_BYTE_SIZE) {
			// Read the first BLOCK_BYTE_SIZE bytes from the in file
			memcpy(plainBlock,&inBuff[i],BLOCK_BYTE_SIZE);
			
			//decrypt the message block
			memcpy(encryptBlock,plainBlock,BLOCK_BYTE_SIZE);
			des_encrypt1((long unsigned int *)encryptBlock,key,DEC);
		
			// XOR them with the previous output cipher text (or IV)
			for (int j = 0; j < BLOCK_BYTE_SIZE; j++) {
				XORBlock[j] = encryptBlock[j]^XOR[j];
			}
			// Encrypt the message block
			//memcpy(encryptBlock,XORBlock,BLOCK_BYTE_SIZE);

			//des_encrypt1((unsigned int *)encryptBlock,key,ENC);
			// Write to out buffer
			memcpy(&outBuff[i],XORBlock,BLOCK_BYTE_SIZE);
			// Update the cbc_key
			memcpy(XOR,plainBlock,BLOCK_BYTE_SIZE);
		}
		
		//pick timing conclusion right after the cipher
		gettimeofday(&et, NULL);
		
    }
    
    //pick timing conclusion right after the cipher
    gettimeofday(&et, NULL);

	int elapsed = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
	printf("encryption time: %d micro seconds\n",elapsed);
	
	// Write hex to console then output file
	/*printf("DES CipherText:\n");
	int i = 0;
	for (i = 0; i < inFileSizePadded-1; i += BLOCK_BYTE_SIZE) {
		for (int j = 0; j < BLOCK_BYTE_SIZE; j+=2) {
			printf("%02x%02x ", outBuff[i+j], outBuff[i+j+1]);	
		}
		printf("%d\n",i);
	}
	*/
	
	FILE * outFile = fopen(argv[OUT_FILE_ARG],"w");
	//fprintf(outFile,"%s",outBuff);
	fwrite(outBuff, 1, sizeof(outBuff), outFile);
	fclose(outFile);

	return 0;
}
