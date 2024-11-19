

// Performs encryption using AES 128-bit

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <omp.h>
#include<algorithm> 
#include "structures.h"

using namespace std;

// Serves as the initial round during encryption

// AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
void SubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) {
		state[i] = s[state[i]];
	}
}

// Shift left, adds diffusion
void ShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];
	
	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];
	
	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
void MixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESEncrypt()
 */
void Round(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

 // Same as Round() except it doesn't mix columns
void FinalRound(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char state[16]; // Stores the first 16 bytes of original message

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	int numberOfRounds = 9;

	AddRoundKey(state, expandedKey); // Initial round

	for (int i = 0; i < numberOfRounds; i++) {
		Round(state, expandedKey + (16 * (i+1)));
	}

	FinalRound(state, expandedKey + 160);

	// Copy encrypted state to buffer
	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
}


int main() {
    cout << "========================================" << endl;
    cout << " -------- Parallel Execution --------   " << endl;
    cout << "                 of " << endl;
    cout << " ------ AES Encryption Algorithm -----  " <<endl;
    cout << "========================================" << endl;

    const char* inputFile = "input.txt";
    const size_t blockSize = 16;

    ifstream inputFileStream(inputFile, ios::in | ios::binary);
    if (!inputFileStream.is_open()) {
        cerr << "Error: Unable to open input file '" << inputFile << "'" << endl;
        return 1;
    }

    inputFileStream.seekg(0, ios::end);
    size_t inputFileSize = inputFileStream.tellg();
    inputFileStream.seekg(0, ios::beg);

    unsigned char* inputData = new unsigned char[inputFileSize];
    inputFileStream.read((char*)inputData, inputFileSize);
    inputFileStream.close();

    unsigned char* encryptedOutput = new unsigned char[inputFileSize];

    // Load key file once before the parallel region
    string str;
    ifstream keyFile("keyfile", ios::in | ios::binary);
    if (keyFile.is_open()) {
        getline(keyFile, str);
        keyFile.close();
    } else {
        cerr << "Unable to open key file" << endl;
        delete[] inputData;
        delete[] encryptedOutput;
        return 1;
    }

    istringstream hex_chars_stream(str);
    unsigned char key[16];
    int i = 0;
    unsigned int c;
    while (hex_chars_stream >> hex >> c && i < 16) {
        key[i] = c;
        i++;
    }

    unsigned char expandedKey[176];
    KeyExpansion(key, expandedKey);

    size_t blockCount = (inputFileSize + blockSize - 1) / blockSize;

    int usedThreads = 0; 
    // Data parallelization using OpenMP
    double start = omp_get_wtime();

    // Get and print the number of available processors
    int numProcs = omp_get_num_procs();
    cout << "Number of processors available: " << numProcs << endl;

    #pragma omp parallel for num_threads(8)
    for (size_t blockIndex = 0; blockIndex < blockCount; ++blockIndex) {
        size_t bytesRead = min(blockSize, inputFileSize - blockIndex * blockSize);
        unsigned char* block = new unsigned char[blockSize];
        copy(inputData + blockIndex * blockSize, inputData + blockIndex * blockSize + bytesRead, block);

        if (bytesRead < blockSize) {
            memset(block + bytesRead, 0, blockSize - bytesRead);  // Simple padding
        }

        unsigned char* encryptedBlock = new unsigned char[blockSize];

        AESEncrypt(block, expandedKey, encryptedBlock);

        // Use critical section for copying back encrypted block
        #pragma omp critical
        {
            // int numThreads = omp_get_num_threads();
            // int threadID = omp_get_thread_num();
            // cout << "Thread " << threadID << " of " << numThreads << " is processing block " << blockIndex << endl;
            usedThreads = omp_get_num_threads();

            copy(encryptedBlock, encryptedBlock + blockSize, encryptedOutput + blockIndex * blockSize);
            delete[] block;
            delete[] encryptedBlock;
        }
    }
    double end = omp_get_wtime();
    cout << "Number of threads used: " << usedThreads << endl;

    cout << "Execution time: " << (end - start)*1000 << " milliseconds" << endl;
    
    double averageTimePerThread = (end - start)*1000 / 8;
    cout << "Average time per thread: " << averageTimePerThread << " milliseconds" << endl;

    ofstream outputFileStream("encrypted.aes", ios::out | ios::binary);
    if (outputFileStream.is_open()) {
        outputFileStream.write((char*)encryptedOutput, inputFileSize);
        outputFileStream.close();
        cout << "Encrypted output written to 'encrypted.aes'" << endl;
    } else {
        cerr << "Error: Unable to open output file 'encrypted.aes'" << endl;
    }

    delete[] inputData;
    delete[] encryptedOutput;

    return 0;
}