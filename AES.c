#include <stdio.h>
#include <stdlib.h>
#include "AES.h"  				// This header file defines AES functions and types

int main()
{
    unsigned char state[4][4]; // State array for AES
    
    // 128-bit key 
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
     								
	// 128-bit input 
    unsigned char input[16] = 
    { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };                        

   // Copy input array into the state array in column order
    
    for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            state[i][j] = input[4 * j + i];
        }
    }

    // Generate key schedule
    
    word w[44];
    KeyExpansion((word*)key, w);

    
   // Perform AES encryption and decryption
    
    Cipher(state, w);
    DeCipher(state, w);

   // Print the state array
    
    for (int i = 0; i < 4; i++)
    {
        printf("%d: ", i);
        for (int j = 0; j < 4; j++)
        {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }

    return 0;
    
}

