#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>

#define ENC 1
#define DEC 0
#define BLOCK_BYTE_SIZE 8
#define MODE 0 //This can be changed to do ENC or DEC

int main(int argc, char * argv[])
{
	if (argc != 5) {
		printf("Incorrect number of arguments.\n");
		exit(1);
	}

	if (strlen(argv[1]) != 16 || strlen(argv[2]) != 16) {
		printf("Invalid length of IV or key.\n");
		exit(1);
	}

	FILE * inputFile = fopen(argv[3], "r");
	if (inputFile == NULL) {
		printf("Input file not found.\n");
		exit(1);
	}

	fseek(inputFile, 0, SEEK_END); //move file pointer to end of file to get file size
	int fileSize = ftell(inputFile);
	int fileSizeBlocksLength = (int)ceil((double)fileSize/8.0)*8.0; //fill the file length to be divided by 8 (a block)
	fseek(inputFile,0,SEEK_SET); //move file poinnter to start of file to read file in array
	char inputArray[fileSizeBlocksLength];
	memset(&inputArray[0], 0, fileSizeBlocksLength);
	int i = 0;
	for(i=0;i<fileSize;i++) fscanf(inputFile, "%c", &inputArray[i]); //read file into array
	fclose(inputFile);

	unsigned char IV[8];
	unsigned char cbc[8];
	for (i=0; i<BLOCK_BYTE_SIZE; i++) {
    	sscanf(argv[1]+(2*i), "%2hhx", &IV[i]);
    	sscanf(argv[2]+(2*i), "%2hhx", &cbc[i]);
	}

	des_key_schedule key;
	if (des_set_key_checked(&cbc, key) != 0) {
		printf("DES key create failure.\n");
		exit(1);
	}

	char encryptedArray[fileSizeBlocksLength];
	memset(encryptedArray, 0, fileSizeBlocksLength);
	char XORArray[8];
	char textArray[8];
	char XORedArray[8];
	char encryptBlockArray[8];
	struct timeval start; //for use of gettimeofday
	struct timeval end; //for use of gettimeofday

	memcpy(XORArray,IV,8);//take 8 byte of IV for the first XOR operation

	int j = 0;
	if(MODE == ENC) { //Encrypt
		gettimeofday(&start, NULL);//get start time of encrypt
		for(i=0;i<fileSizeBlocksLength;i+=8) {
			memcpy(textArray, &inputArray[i], 8); //copy 8 bytes of text into textArray
			for(j=0;j<8;j++) XORedArray[j] = textArray[j]^XORArray[j];
			memcpy(encryptBlockArray, XORedArray, 8);//copy XOR result to encrypt
			des_encrypt1((long unsigned int*)encryptBlockArray,key,ENC);
			memcpy(&XORArray[0], encryptBlockArray, 8);//copy encrypted block to be used as next XOR source
			memcpy(&encryptedArray[i], encryptBlockArray, 8);//copy encrypted block to output
		}
		gettimeofday(&end, NULL);
	} else if(MODE == DEC) { //Decrypt
		gettimeofday(&start, NULL);
		for(i=0;i<fileSizeBlocksLength;i+=8) {
			memcpy(textArray, &inputArray[i], 8);
			memcpy(encryptBlockArray, textArray, 8);
			des_encrypt1((long unsigned int*)encryptBlockArray,key,DEC);
			for(j=0;j<8;j++) XORedArray[j] = encryptBlockArray[j]^XORArray[j];
			memcpy(&XORArray[0], textArray, 8);
			memcpy(&encryptedArray[i], XORedArray, 8);
		}
		gettimeofday(&end, NULL);
	} else {
		printf("Mode error.\n");
		exit(1);
	}
	FILE * outputFile = fopen(argv[4],"w");
	fwrite(encryptedArray, 1, sizeof(encryptedArray), outputFile);
	fclose(outputFile);

	long long timeSpent = ((end.tv_sec - start.tv_sec)*1000000)+(end.tv_usec-start.tv_usec);
	printf("Time Spent on DES ENC/DEC: %lld μm.\n", timeSpent);

	return 0;
}
