
// Performs decryption using AES 128-bit

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <omp.h>
#include<chrono>
#include "structures.h"

using namespace std;

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 * So basically does the same as AddRoundKey in the encryption
 */
void SubRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
void InverseMixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

// Shifts rows right (rather than left) for decryption
void ShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
void SubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
void Round(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

// Same as Round() but no InverseMixColumns
void InitialRound(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	ShiftRows(state);
	SubBytes(state);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
void AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage)
{
	unsigned char state[16]; // Stores the first 16 bytes of encrypted message

	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey+160);

	int numberOfRounds = 9;

	for (int i = 8; i >= 0; i--) {
		Round(state, expandedKey + (16 * (i + 1)));
	}

	SubRoundKey(state, expandedKey); // Final round

	// Copy decrypted state to buffer
	for (int i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
}


int main() {
    cout << "=============================" << endl;
    cout << " -------- Parallel Execution --------   " << endl;
    cout << " ------------ of ------------   " << endl;
    cout << " --- AES Decryption Algorithm ---  "<< endl; 
    cout << "=============================" << endl;

    const char* inputFile = "encrypted.aes";
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

    unsigned char* decryptedOutput = new unsigned char[inputFileSize];

    // Load key file once before the parallel region
    string str;
    ifstream keyFile("keyfile", ios::in | ios::binary);
    if (keyFile.is_open()) {
        getline(keyFile, str);
        keyFile.close();
    } else {
        cerr << "Unable to open key file" << endl;
        delete[] inputData;
        delete[] decryptedOutput;
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
            // No need to pad the encrypted data
        }

        unsigned char* decryptedBlock = new unsigned char[blockSize];

        AESDecrypt(block, expandedKey, decryptedBlock);

        // Use critical section for copying back decrypted block
        #pragma omp critical
        {
            usedThreads = omp_get_num_threads();

            copy(decryptedBlock, decryptedBlock + blockSize, decryptedOutput + blockIndex * blockSize);
            delete[] block;
            delete[] decryptedBlock;
        }
    }
    double end = omp_get_wtime();
    cout << "Number of threads used: " << usedThreads << endl;

    cout << "Execution time: " << (end - start)*1000 << " milliseconds" << endl;

    double averageTimePerThread = (end - start)*1000 / 8;
    cout << "Average time per thread: " << averageTimePerThread << " milliseconds" << endl;

    ofstream outputFileStream("decrypted_message.txt", ios::out | ios::binary);
    if (outputFileStream.is_open()) {
        outputFileStream.write((char*)decryptedOutput, inputFileSize);
        outputFileStream.close();
        cout << "Decrypted output written to 'decrypted_message.txt'" << endl;
    } else {
        cerr << "Error: Unable to open output file 'decrypted_message.txt'" << endl;
    }

    delete[] inputData;
    delete[] decryptedOutput;

    return 0;
}