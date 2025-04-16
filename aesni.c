#include <wmmintrin.h>
#include<stdio.h>
#include<emmintrin.h>

__m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
	{

__m128i temp3;
temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
temp3 = _mm_slli_si128 (temp1, 0x04);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x04);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x04);
temp1 = _mm_xor_si128 (temp1, temp3);
temp1 = _mm_xor_si128 (temp1, temp2);
return temp1;
	}
	
	
void AES_128_Key_Expansion (const unsigned char *userkey, unsigned char *key) 		//keyexpansion function
	{
	__m128i temp1, temp2;
	__m128i *Key_Schedule = (__m128i*)key;
	temp1 = _mm_loadu_si128((__m128i*)userkey);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x01);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x02);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x04);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x08);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
	temp1 = AES_128_ASSIST(temp1, temp2);
	Key_Schedule[10] = temp1;
	}	
	
	void aesenc(unsigned char *key, unsigned char *input, unsigned char *output)		//Encryption Function
	{
		__m128i v = _mm_loadu_si128((__m128i*)input);

	v= _mm_xor_si128(v,((__m128i *)key)[0]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[1]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[2]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[3]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[4]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[5]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[6]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[7]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[8]);
	v= _mm_aesenc_si128(v,((__m128i *)key)[9]);
	v= _mm_aesenclast_si128(v,((__m128i *)key)[10]);	
	
	
	_mm_storeu_si128((__m128i *)output, v);
	
	}
	
	void aesdec(unsigned char *key, unsigned char *output, unsigned char *plaintext)		//Decryption Function

	{
	 __m128i w = _mm_loadu_si128((__m128i *)output);
	w= _mm_xor_si128(w,((__m128i *)key)[10]);
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[9]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[8]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[7]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[6]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[5]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[4]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[3]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[2]));
	w= _mm_aesdec_si128(w,_mm_aesimc_si128(((__m128i *)key)[1]));	
	w= _mm_aesdeclast_si128(w,(((__m128i *)key)[0]));
	
	_mm_storeu_si128((__m128i *)plaintext, w);
		
	}
	
int main ()
{
unsigned char key[176], output[16], plaintext[16]; 
    
    // 128-bit key 
    unsigned char userkey[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
     								
	// 128-bit input 
 unsigned char input[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };                
 //Printing the message which is in input
    /*for (int i = 0; i < 16; i++)
    {
        printf("%02x  ", input[i]);
    }
printf("\n");*/

AES_128_Key_Expansion (userkey, key);
//Doing Encryption on input and ciphertext is in output  
aesenc(key, input, output);
//Doing Decryption on output and message is in plaintext  
aesdec(key, output,plaintext);
//Printing decrypted ciphertext whis is in plaintext
for (int i = 0; i < 16; i++)
    {
        printf("%02x  ", plaintext[i]);
    }
//checking equality of input and plaintext, for correctness. 
 return(0);
}
