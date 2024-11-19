# Parallelization of AES Encryption and Decryption

## Overview

This project demonstrates the parallelization of AES encryption and decryption using OpenMP. The goal is to improve the performance of the encryption and decryption process by utilizing multiple CPU cores.

## What is AES?

AES (Advanced Encryption Standard) is a widely used symmetric-key block cipher that encrypts and decrypts data in blocks of 128 bits. It is a secure encryption algorithm that is widely used in various applications, including secure data transmission and storage.

## Parallelization Concept

Parallelization is a technique used to improve the performance of a program by dividing the workload among multiple CPU cores. In this project, we use OpenMP to parallelize the AES encryption and decryption process. OpenMP is a directive-based parallel programming model that allows developers to easily parallelize loops and other code regions.

## How it Works

The project consists of two main components:

1.  **AES Encryption**: The encryption process takes a plaintext message and a secret key as input and produces a ciphertext message as output.
2.  **AES Decryption**: The decryption process takes a ciphertext message and a secret key as input and produces a plaintext message as output.

The parallelization of the AES encryption and decryption process is achieved by dividing the input data into blocks of size `blockSize` (16 bytes) and processing each block in parallel using a loop. The `#pragma omp parallel for` directive is used to parallelize the loop, and the `#pragma omp critical` directive is used to ensure that the output is correct.

## Requirements

To run this project, you need:

*   **OpenMP**: OpenMP is a directive-based parallel programming model that allows developers to easily parallelize loops and other code regions.
*   **C++ Compiler**: A C++ compiler that supports OpenMP is required to compile the project.
*   **AES Library**: An AES library is required to implement the AES encryption and decryption algorithm.

## Usage

To use this project, follow these steps:  

1. **Clone the Repository**:  
   ```bash
   git clone https://github.com/piyush-ghanghav/Parallel-AES-Implementation.git
   cd https://github.com/piyush-ghanghav Parallel-AES-Implementation.git
   ```

2. **Compile the Code**:  
   ```bash
   g++ -fopenmp -o parallel_encrypt parallel_encrypt.cpp
   ```

3. **Run the Program**:  
   ```bash
   ./parallel_encrypt 
   ```  
   
   #### Adjust Files as Necessary  

- **`<input_file>`**: File to encrypt.  
- **`<output_file>`**: Generated encrypted file (e.g., `encrypted.aes`, `decrypted_message.txt`).  
- **`<key>`**: 128-bit, 192-bit, or 256-bit key.  
  

## License

This project is licensed under the MIT License.

## Acknowledgments

This project was developed using the OpenMP parallel programming model and the AES encryption and decryption algorithm. The project is intended for educational purposes only.

By using this project, you acknowledge that you have read and understood the terms and conditions of the MIT License.