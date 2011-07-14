/*
******************************************************************
**       Advanced Encryption Standard implementation in C++.    **
**       By Anoop Singh & Ankit Malani			                **                         
******************************************************************
This is the source code for decryption using the latest AES algorithm.
AES algorithm is also called Rijndael algorithm. AES algorithm is
recommended for non-classified use by the National Institute of Standards
and Technology(NIST), USA. Now-a-days AES is being used for almost
all encryption applications all around the world.

THE MAIN FEATURE OF THIS AES ENCRYPTION PROGRAM IS NOT EFFICIENCY; IT
IS SIMPLICITY AND READABILITY. THIS SOURCE CODE IS PROVIDED FOR ALL
TO UNDERSTAND THE AES ALGORITHM.

Comments are provided as needed to understand the program. But the
user must read some AES documentation to understand the underlying
theory correctly.

It is not possible to describe the complete AES algorithm in detail
here. For the complete description of the algorithm, point your
browser to:
http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Find the Wikipedia page of AES at:
http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
******************************************************************
*/

// Used for giving output to the screen.
#include<iostream>
#include<fstream>
#include<ios>
#include<iomanip>
#include<algorithm>
#include<time.h>
#include<stdio.h>

// include TBB header files
#include "tbb/task_scheduler_init.h"
#include "tbb/parallel_for.h"
#include "tbb/blocked_range.h"

using namespace std;
using namespace tbb;

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// Multiplty is a macro used to multiply numbers in the field GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))


// in - it is the array that holds the CipherText to be decrypted.
// out - it is the array that holds the output of the for decryption.
// state - the array that holds the intermediate results during decryption.
unsigned char in[16], out[16], state[4][4];
// The Key input to the AES Program

unsigned char Key[32];
// The array that stores the round keys.
unsigned char RoundKey[240];


//for optimization of every for loop, a class is required

class Rounds
{
	int m;
public:
	void operator()(const blocked_range<size_t>& r)		//overloading() operator
	const{
			for(size_t i=r.begin();i!=r.end();i++)
			{
				RoundKey[i*4]=Key[i*4];
						RoundKey[i*4+1]=Key[i*4+1];
						RoundKey[i*4+2]=Key[i*4+2];
						RoundKey[i*4+3]=Key[i*4+3];
	
				
			}//for
		}//const
	//constructor so that required parameters can be passed
	
	Rounds(int n) : m(n) {};
			
};


//count1 represents the number of rounds required, eah working on 16 bits
int count1=0;

// The number of rounds in AES Cipher. It is simply initiated to zero. The actual value is recieved in the program.
int Nr=0;

// The number of 32 bit words in the key. It is simply initiated to zero. The actual value is recieved in the program.
int Nk=0;

//pre-declaring the required function

void print(ofstream &, int);		//write the output to the file
void inttohex(ofstream &, int);	//converts an int into hex

int getSBoxInvert(int num)
{
int rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

return rsbox[num];
}

int getSBoxValue(int num)
{
	int sbox[256] =   {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	return sbox[num];
}

// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
int Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
void KeyExpansion()
{
	int i,j;
	unsigned char temp[4],k;

	parallel_for(blocked_range<size_t>(0,Nk),Rounds(2),auto_partitioner());
	// The first round key is the key itself.
/*	for(i=0;i<Nk;i++)
	{
		RoundKey[i*4]=Key[i*4];
		RoundKey[i*4+1]=Key[i*4+1];
		RoundKey[i*4+2]=Key[i*4+2];
		RoundKey[i*4+3]=Key[i*4+3];
	}
*/
	i=Nk;
	// All other round keys are found from the previous round keys.
	while (i < (Nb * (Nr+1)))
	{
		for(j=0;j<4;j++)
		{
			temp[j]=RoundKey[(i-1) * 4 + j];
		}
		if (i % Nk == 0)
		{
			// This function rotates the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			{
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
			}

			// SubWord() is a function that takes a four-byte input word and
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			{
				temp[0]=getSBoxValue(temp[0]);
				temp[1]=getSBoxValue(temp[1]);
				temp[2]=getSBoxValue(temp[2]);
				temp[3]=getSBoxValue(temp[3]);
			}

			temp[0] =  temp[0] ^ Rcon[i/Nk];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			// Function Subword()
			{
				temp[0]=getSBoxValue(temp[0]);
				temp[1]=getSBoxValue(temp[1]);
				temp[2]=getSBoxValue(temp[2]);
				temp[3]=getSBoxValue(temp[3]);
			}
		}
		RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0];
		RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1];
		RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2];
		RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3];
		i++;
	}
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(int round)
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void InvSubBytes()
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[i][j] = getSBoxInvert(state[i][j]);

		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void InvShiftRows()
{
	unsigned char temp;

	// Rotate first row 1 columns to right
	temp=state[1][3];
	state[1][3]=state[1][2];
	state[1][2]=state[1][1];
	state[1][1]=state[1][0];
	state[1][0]=temp;

	// Rotate second row 2 columns to right	
	temp=state[2][0];
	state[2][0]=state[2][2];
	state[2][2]=temp;

	temp=state[2][1];
	state[2][1]=state[2][3];
	state[2][3]=temp;

	// Rotate third row 3 columns to right
	temp=state[3][0];
	state[3][0]=state[3][1];
	state[3][1]=state[3][2];
	state[3][2]=state[3][3];
	state[3][3]=temp;
}


// converts an int to hexadecimal and calls the print function to write the same to a file
void inttohex(ofstream &o, int a)
{
	int b=16,d;
	if(a==0)
		o<<"00";
	if(a<=15)
		o<<"0";
	while(a)
	{
		if(a%16 ==0)
		{
			d=a/16;
			if(d>=1 && d<16)
			{
				print(o, d);
				o<<"0";
			}
			a=0;
		}
		else if(a>15)
		{
			if((a/b)!=0)
			{
				d=a/b;
				a=a%16;
				print(o, d);
			}

		}
		else
		{
			d=a;
			a=0;
			print(o, d);
		}
	}

	//o<<" ";
	return;
}


//prints the output of previous function to file
void print(ofstream &o, int d)
{
	if(d<10)       o<<d;
	else if(d==10) o<<"a";
	else if(d==11) o<<"b";
	else if(d==12) o<<"c";
	else if(d==13) o<<"d";
	else if(d==14) o<<"e";
	else if(d==15) o<<"f";

	return;
}

// MixColumns function mixes the columns of the state matrix and InvMixColumns do the inverse of it
void InvMixColumns()
{
	int i;
	unsigned char a,b,c,d;
	for(i=0;i<4;i++)
	{
	
		a = state[0][i];
		b = state[1][i];
		c = state[2][i];
		d = state[3][i];

		
		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// InvCipher is the main function that decrypts the CipherText.
void InvCipher()
{
	int i,j,round=0;

	//Copy the input CipherText to state array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[j][i] = in[i*4 + j];
		}
	}

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr); 

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.

	for(round=Nr-1;round>0;round--)
	{
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(round);
		InvMixColumns();
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(0);

	// The decryption process is over.
	// Copy the state array to output array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			out[i*4+j]=state[j][i];
		}
	}
}

//Routine to find out the number of rounds required first and then
//storing it in count1
void getme()
{
	int i=0;
	unsigned long num_char=0;
	char ch;
	ifstream fp1;
	fp1.open("c:/output1.txt");

	fp1.get(ch);

	while (!fp1.eof())
	{
		num_char++;
		fp1.get(ch);
	}

	count1=(num_char/16)+1;
	count1/=3;

	fp1.close();
}

int main()
{
	//time variables
	time_t start,end;
	double dif;

	//start time
	time (&start);

	//Initializes the task scheduler. Must have before starting on any threading operations
	task_scheduler_init init;
	getme();
	ifstream fp1;
	ofstream fp2;
	fp1.open("c:/output1.txt");
	fp2.open("c:/orig1.txt");

	int i;

	Nr=128;
	// Calculate Nk and Nr

LABEL:  count1--;

	Nr=128;
	Nk = Nr / 32;
	Nr = Nk + 6;

	// The array temp stores the key.
	unsigned char temp[32] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};

	// Copy the Key and CipherText
	//parallel_for(blocked_range<size_t>(0,Nk*4),Convkey(2),auto_partitioner());
	for(i=0;i<Nk*4;i++)
		Key[i]=temp[i];
	/*Inefficiency is introduced intentionally here. Here, 2 characters are read from the hex file
	and their equivalent is stored in the in array
	*/

	for(i=0;i<Nb*4;i++)
	{
		char ch[3], m;
		
		fp1.get(ch, 3);
		fp1.get(m);
	  if(ch[0]=='0' && ch[1]=='0')
		in[i]=0x00;
	  if(ch[0]=='0' && ch[1]=='1')
		in[i]=0x01;
	  if(ch[0]=='0' && ch[1]=='2')
		in[i]=0x02;
	  if(ch[0]=='0' && ch[1]=='3')
		in[i]=0x03;
	  if(ch[0]=='0' && ch[1]=='4')
		in[i]=0x04;
	  if(ch[0]=='0' && ch[1]=='5')
		in[i]=0x05;
	  if(ch[0]=='0' && ch[1]=='6')
		in[i]=0x06;
	  if(ch[0]=='0' && ch[1]=='7')
		in[i]=0x07;
	  if(ch[0]=='0' && ch[1]=='8')
		in[i]=0x08;
	  if(ch[0]=='0' && ch[1]=='9')
		in[i]=0x09;
	  if(ch[0]=='0' && ch[1]=='a')
		in[i]=0x0a;
	  if(ch[0]=='0' && ch[1]=='b')
		in[i]=0x0b;
	  if(ch[0]=='0' && ch[1]=='c')
		in[i]=0x0c;
	  if(ch[0]=='0' && ch[1]=='d')
		in[i]=0x0d;
	  if(ch[0]=='0' && ch[1]=='e')
		in[i]=0x0e;
	  if(ch[0]=='0' && ch[1]=='f')
		in[i]=0x0f;


	  if(ch[0]=='1' && ch[1]=='0')
		in[i]=0x10;
	  if(ch[0]=='1' && ch[1]=='1')
		in[i]=0x11;
	  if(ch[0]=='1' && ch[1]=='2')
		in[i]=0x12;
	  if(ch[0]=='1' && ch[1]=='3')
		in[i]=0x13;
	  if(ch[0]=='1' && ch[1]=='4')
		in[i]=0x14;
	  if(ch[0]=='1' && ch[1]=='5')
		in[i]=0x15;
	  if(ch[0]=='1' && ch[1]=='6')
		in[i]=0x16;
	  if(ch[0]=='1' && ch[1]=='7')
		in[i]=0x17;
	  if(ch[0]=='1' && ch[1]=='8')
		in[i]=0x18;
	  if(ch[0]=='1' && ch[1]=='9')
		in[i]=0x19;
	  if(ch[0]=='1' && ch[1]=='a')
		in[i]=0x1a;
	  if(ch[0]=='1' && ch[1]=='b')
		in[i]=0x1b;
	  if(ch[0]=='1' && ch[1]=='c')
		in[i]=0x1c;
	  if(ch[0]=='1' && ch[1]=='d')
		in[i]=0x1d;
	  if(ch[0]=='1' && ch[1]=='e')
		in[i]=0x1e;
	  if(ch[0]=='1' && ch[1]=='f')
		in[i]=0x1f;

	  if(ch[0]=='2' && ch[1]=='0')
		in[i]=0x20;
	  if(ch[0]=='2' && ch[1]=='1')
		in[i]=0x21;
	  if(ch[0]=='2' && ch[1]=='2')
		in[i]=0x22;
	  if(ch[0]=='2' && ch[1]=='3')
		in[i]=0x23;
	  if(ch[0]=='2' && ch[1]=='4')
		in[i]=0x24;
	  if(ch[0]=='2' && ch[1]=='5')
		in[i]=0x25;
	  if(ch[0]=='2' && ch[1]=='6')
		in[i]=0x26;
	  if(ch[0]=='2' && ch[1]=='7')
		in[i]=0x27;
	  if(ch[0]=='2' && ch[1]=='8')
		in[i]=0x28;
	  if(ch[0]=='2' && ch[1]=='9')
		in[i]=0x29;
	  if(ch[0]=='2' && ch[1]=='a')
		in[i]=0x2a;
	  if(ch[0]=='2' && ch[1]=='b')
		in[i]=0x2b;
	  if(ch[0]=='2' && ch[1]=='c')
		in[i]=0x2c;
	  if(ch[0]=='2' && ch[1]=='d')
		in[i]=0x2d;
	  if(ch[0]=='2' && ch[1]=='e')
		in[i]=0x2e;
	  if(ch[0]=='2' && ch[1]=='f')
		in[i]=0x2f;

	  if(ch[0]=='3' && ch[1]=='0')
		in[i]=0x30;
	  if(ch[0]=='3' && ch[1]=='1')
		in[i]=0x31;
	  if(ch[0]=='3' && ch[1]=='2')
		in[i]=0x32;
	  if(ch[0]=='3' && ch[1]=='3')
		in[i]=0x33;
	  if(ch[0]=='3' && ch[1]=='4')
		in[i]=0x34;
	  if(ch[0]=='3' && ch[1]=='5')
		in[i]=0x35;
	  if(ch[0]=='3' && ch[1]=='6')
		in[i]=0x36;
	  if(ch[0]=='3' && ch[1]=='7')
		in[i]=0x37;
	  if(ch[0]=='3' && ch[1]=='8')
		in[i]=0x38;
	  if(ch[0]=='3' && ch[1]=='9')
		in[i]=0x39;
	  if(ch[0]=='3' && ch[1]=='a')
		in[i]=0x3a;
	  if(ch[0]=='3' && ch[1]=='b')
		in[i]=0x3b;
	  if(ch[0]=='3' && ch[1]=='c')
		in[i]=0x3c;
	  if(ch[0]=='3' && ch[1]=='d')
		in[i]=0x3d;
	  if(ch[0]=='3' && ch[1]=='e')
		in[i]=0x3e;
	  if(ch[0]=='3' && ch[1]=='f')
		in[i]=0x3f;

	  if(ch[0]=='4' && ch[1]=='0')
		in[i]=0x40;
	  if(ch[0]=='4' && ch[1]=='1')
		in[i]=0x41;
	  if(ch[0]=='4' && ch[1]=='2')
		in[i]=0x42;
	  if(ch[0]=='4' && ch[1]=='3')
		in[i]=0x43;
	  if(ch[0]=='4' && ch[1]=='4')
		in[i]=0x44;
	  if(ch[0]=='4' && ch[1]=='5')
		in[i]=0x45;
	  if(ch[0]=='4' && ch[1]=='6')
		in[i]=0x46;
	  if(ch[0]=='4' && ch[1]=='7')
		in[i]=0x47;
	  if(ch[0]=='4' && ch[1]=='8')
		in[i]=0x48;
	  if(ch[0]=='4' && ch[1]=='9')
		in[i]=0x49;
	  if(ch[0]=='4' && ch[1]=='a')
		in[i]=0x4a;
	  if(ch[0]=='4' && ch[1]=='b')
		in[i]=0x4b;
	  if(ch[0]=='4' && ch[1]=='c')
		in[i]=0x4c;
	  if(ch[0]=='4' && ch[1]=='d')
		in[i]=0x4d;
	  if(ch[0]=='4' && ch[1]=='e')
		in[i]=0x4e;
	  if(ch[0]=='4' && ch[1]=='f')
		in[i]=0x4f;

	  if(ch[0]=='5' && ch[1]=='0')
		in[i]=0x50;
	  if(ch[0]=='5' && ch[1]=='1')
		in[i]=0x51;
	  if(ch[0]=='5' && ch[1]=='2')
		in[i]=0x52;
	  if(ch[0]=='5' && ch[1]=='3')
		in[i]=0x53;
	  if(ch[0]=='5' && ch[1]=='4')
		in[i]=0x54;
	  if(ch[0]=='5' && ch[1]=='5')
		in[i]=0x55;
	  if(ch[0]=='5' && ch[1]=='6')
		in[i]=0x56;
	  if(ch[0]=='5' && ch[1]=='7')
		in[i]=0x57;
	  if(ch[0]=='5' && ch[1]=='8')
		in[i]=0x58;
	  if(ch[0]=='5' && ch[1]=='9')
		in[i]=0x59;
	  if(ch[0]=='5' && ch[1]=='a')
		in[i]=0x5a;
	  if(ch[0]=='5' && ch[1]=='b')
		in[i]=0x5b;
	  if(ch[0]=='5' && ch[1]=='c')
		in[i]=0x5c;
	  if(ch[0]=='5' && ch[1]=='d')
		in[i]=0x5d;
	  if(ch[0]=='5' && ch[1]=='e')
		in[i]=0x5e;
	  if(ch[0]=='5' && ch[1]=='f')
		in[i]=0x5f;

	  if(ch[0]=='6' && ch[1]=='0')
		in[i]=0x60;
	  if(ch[0]=='6' && ch[1]=='1')
		in[i]=0x61;
	  if(ch[0]=='6' && ch[1]=='2')
		in[i]=0x62;
	  if(ch[0]=='6' && ch[1]=='3')
		in[i]=0x63;
	  if(ch[0]=='6' && ch[1]=='4')
		in[i]=0x64;
	  if(ch[0]=='6' && ch[1]=='5')
		in[i]=0x65;
	  if(ch[0]=='6' && ch[1]=='6')
		in[i]=0x66;
	  if(ch[0]=='6' && ch[1]=='7')
		in[i]=0x67;
	  if(ch[0]=='6' && ch[1]=='8')
		in[i]=0x68;
	  if(ch[0]=='6' && ch[1]=='9')
		in[i]=0x69;
	  if(ch[0]=='6' && ch[1]=='a')
		in[i]=0x6a;
	  if(ch[0]=='6' && ch[1]=='b')
		in[i]=0x6b;
	  if(ch[0]=='6' && ch[1]=='c')
		in[i]=0x6c;
	  if(ch[0]=='6' && ch[1]=='d')
		in[i]=0x6d;
	  if(ch[0]=='6' && ch[1]=='e')
		in[i]=0x6e;
	  if(ch[0]=='6' && ch[1]=='f')
		in[i]=0x6f;

	  if(ch[0]=='7' && ch[1]=='0')
		in[i]=0x70;
	  if(ch[0]=='7' && ch[1]=='1')
		in[i]=0x71;
	  if(ch[0]=='7' && ch[1]=='2')
		in[i]=0x72;
	  if(ch[0]=='7' && ch[1]=='3')
		in[i]=0x73;
	  if(ch[0]=='7' && ch[1]=='4')
		in[i]=0x74;
	  if(ch[0]=='7' && ch[1]=='5')
		in[i]=0x75;
	  if(ch[0]=='7' && ch[1]=='6')
		in[i]=0x76;
	  if(ch[0]=='7' && ch[1]=='7')
		in[i]=0x77;
	  if(ch[0]=='7' && ch[1]=='8')
		in[i]=0x78;
	  if(ch[0]=='7' && ch[1]=='9')
		in[i]=0x79;
	  if(ch[0]=='7' && ch[1]=='a')
		in[i]=0x7a;
	  if(ch[0]=='7' && ch[1]=='b')
		in[i]=0x7b;
	  if(ch[0]=='7' && ch[1]=='c')
		in[i]=0x7c;
	  if(ch[0]=='7' && ch[1]=='d')
		in[i]=0x7d;
	  if(ch[0]=='7' && ch[1]=='e')
		in[i]=0x7e;
	  if(ch[0]=='7' && ch[1]=='f')
		in[i]=0x7f;

	  if(ch[0]=='8' && ch[1]=='0')
		in[i]=0x80;
	  if(ch[0]=='8' && ch[1]=='1')
		in[i]=0x81;
	  if(ch[0]=='8' && ch[1]=='2')
		in[i]=0x82;
	  if(ch[0]=='8' && ch[1]=='3')
		in[i]=0x83;
	  if(ch[0]=='8' && ch[1]=='4')
		in[i]=0x84;
	  if(ch[0]=='8' && ch[1]=='5')
		in[i]=0x85;
	  if(ch[0]=='8' && ch[1]=='6')
		in[i]=0x86;
	  if(ch[0]=='8' && ch[1]=='7')
		in[i]=0x87;
	  if(ch[0]=='8' && ch[1]=='8')
		in[i]=0x88;
	  if(ch[0]=='8' && ch[1]=='9')
		in[i]=0x89;
	  if(ch[0]=='8' && ch[1]=='a')
		in[i]=0x8a;
	  if(ch[0]=='8' && ch[1]=='b')
		in[i]=0x8b;
	  if(ch[0]=='8' && ch[1]=='c')
		in[i]=0x8c;
	  if(ch[0]=='8' && ch[1]=='d')
		in[i]=0x8d;
	  if(ch[0]=='8' && ch[1]=='e')
		in[i]=0x8e;
	  if(ch[0]=='8' && ch[1]=='f')
		in[i]=0x8f;


	  if(ch[0]=='9' && ch[1]=='0')
		in[i]=0x90;
	  if(ch[0]=='9' && ch[1]=='1')
		in[i]=0x91;
	  if(ch[0]=='9' && ch[1]=='2')
		in[i]=0x92;
	  if(ch[0]=='9' && ch[1]=='3')
		in[i]=0x93;
	  if(ch[0]=='9' && ch[1]=='4')
		in[i]=0x94;
	  if(ch[0]=='9' && ch[1]=='5')
		in[i]=0x95;
	  if(ch[0]=='9' && ch[1]=='6')
		in[i]=0x96;
	  if(ch[0]=='9' && ch[1]=='7')
		in[i]=0x97;
	  if(ch[0]=='9' && ch[1]=='8')
		in[i]=0x98;
	  if(ch[0]=='9' && ch[1]=='9')
		in[i]=0x99;
	  if(ch[0]=='9' && ch[1]=='a')
		in[i]=0x9a;
	  if(ch[0]=='9' && ch[1]=='b')
		in[i]=0x9b;
	  if(ch[0]=='9' && ch[1]=='c')
		in[i]=0x9c;
	  if(ch[0]=='9' && ch[1]=='d')
		in[i]=0x9d;
	  if(ch[0]=='9' && ch[1]=='e')
		in[i]=0x9e;
	  if(ch[0]=='9' && ch[1]=='f')
		in[i]=0x9f;


	  if(ch[0]=='a' && ch[1]=='0')
		in[i]=0xa0;
	  if(ch[0]=='a' && ch[1]=='1')
		in[i]=0xa1;
	  if(ch[0]=='a' && ch[1]=='2')
		in[i]=0xa2;
	  if(ch[0]=='a' && ch[1]=='3')
		in[i]=0xa3;
	  if(ch[0]=='a' && ch[1]=='4')
		in[i]=0xa4;
	  if(ch[0]=='a' && ch[1]=='5')
		in[i]=0xa5;
	  if(ch[0]=='a' && ch[1]=='6')
		in[i]=0xa6;
	  if(ch[0]=='a' && ch[1]=='7')
		in[i]=0xa7;
	  if(ch[0]=='a' && ch[1]=='8')
		in[i]=0xa8;
	  if(ch[0]=='a' && ch[1]=='9')
		in[i]=0xa9;
	  if(ch[0]=='a' && ch[1]=='a')
		in[i]=0xaa;
	  if(ch[0]=='a' && ch[1]=='b')
		in[i]=0xab;
	  if(ch[0]=='a' && ch[1]=='c')
		in[i]=0xac;
	  if(ch[0]=='a' && ch[1]=='d')
		in[i]=0xad;
	  if(ch[0]=='a' && ch[1]=='e')
		in[i]=0xae;
	  if(ch[0]=='a' && ch[1]=='f')
		in[i]=0xaf;


	  if(ch[0]=='b' && ch[1]=='0')
		in[i]=0xb0;
	  if(ch[0]=='b' && ch[1]=='1')
		in[i]=0xb1;
	  if(ch[0]=='b' && ch[1]=='2')
		in[i]=0xb2;
	  if(ch[0]=='b' && ch[1]=='3')
		in[i]=0xb3;
	  if(ch[0]=='b' && ch[1]=='4')
		in[i]=0xb4;
	  if(ch[0]=='b' && ch[1]=='5')
		in[i]=0xb5;
	  if(ch[0]=='b' && ch[1]=='6')
		in[i]=0xb6;
	  if(ch[0]=='b' && ch[1]=='7')
		in[i]=0xb7;
	  if(ch[0]=='b' && ch[1]=='8')
		in[i]=0xb8;
	  if(ch[0]=='b' && ch[1]=='9')
		in[i]=0xb9;
	  if(ch[0]=='b' && ch[1]=='a')
		in[i]=0xba;
	  if(ch[0]=='b' && ch[1]=='b')
		in[i]=0xbb;
	  if(ch[0]=='b' && ch[1]=='c')
		in[i]=0xbc;
	  if(ch[0]=='b' && ch[1]=='d')
		in[i]=0xbd;
	  if(ch[0]=='b' && ch[1]=='e')
		in[i]=0xbe;
	  if(ch[0]=='b' && ch[1]=='f')
		in[i]=0xbf;


	  if(ch[0]=='c' && ch[1]=='0')
		in[i]=0xc0;
	  if(ch[0]=='c' && ch[1]=='1')
		in[i]=0xc1;
	  if(ch[0]=='c' && ch[1]=='2')
		in[i]=0xc2;
	  if(ch[0]=='c' && ch[1]=='3')
		in[i]=0xc3;
	  if(ch[0]=='c' && ch[1]=='4')
		in[i]=0xc4;
	  if(ch[0]=='c' && ch[1]=='5')
		in[i]=0xc5;
	  if(ch[0]=='c' && ch[1]=='6')
		in[i]=0xc6;
	  if(ch[0]=='c' && ch[1]=='7')
		in[i]=0xc7;
	  if(ch[0]=='c' && ch[1]=='8')
		in[i]=0xc8;
	  if(ch[0]=='c' && ch[1]=='9')
		in[i]=0xc9;
	  if(ch[0]=='c' && ch[1]=='a')
		in[i]=0xca;
	  if(ch[0]=='c' && ch[1]=='b')
		in[i]=0xcb;
	  if(ch[0]=='c' && ch[1]=='c')
		in[i]=0xcc;
	  if(ch[0]=='c' && ch[1]=='d')
		in[i]=0xcd;
	  if(ch[0]=='c' && ch[1]=='e')
		in[i]=0xce;
	  if(ch[0]=='c' && ch[1]=='f')
		in[i]=0xcf;


	  if(ch[0]=='d' && ch[1]=='0')
		in[i]=0xd0;
	  if(ch[0]=='d' && ch[1]=='1')
		in[i]=0xd1;
	  if(ch[0]=='d' && ch[1]=='2')
		in[i]=0xd2;
	  if(ch[0]=='d' && ch[1]=='3')
		in[i]=0xd3;
	  if(ch[0]=='d' && ch[1]=='4')
		in[i]=0xd4;
	  if(ch[0]=='d' && ch[1]=='5')
		in[i]=0xd5;
	  if(ch[0]=='d' && ch[1]=='6')
		in[i]=0xd6;
	  if(ch[0]=='d' && ch[1]=='7')
		in[i]=0xd7;
	  if(ch[0]=='d' && ch[1]=='8')
		in[i]=0xd8;
	  if(ch[0]=='d' && ch[1]=='9')
		in[i]=0xd9;
	  if(ch[0]=='d' && ch[1]=='a')
		in[i]=0xda;
	  if(ch[0]=='d' && ch[1]=='b')
		in[i]=0xdb;
	  if(ch[0]=='d' && ch[1]=='c')
		in[i]=0xdc;
	  if(ch[0]=='d' && ch[1]=='d')
		in[i]=0xdd;
	  if(ch[0]=='d' && ch[1]=='e')
		in[i]=0xde;
	  if(ch[0]=='d' && ch[1]=='f')
		in[i]=0xdf;


	  if(ch[0]=='e' && ch[1]=='0')
		in[i]=0xe0;
	  if(ch[0]=='e' && ch[1]=='1')
		in[i]=0xe1;
	  if(ch[0]=='e' && ch[1]=='2')
		in[i]=0xe2;
	  if(ch[0]=='e' && ch[1]=='3')
		in[i]=0xe3;
	  if(ch[0]=='e' && ch[1]=='4')
		in[i]=0xe4;
	  if(ch[0]=='e' && ch[1]=='5')
		in[i]=0xe5;
	  if(ch[0]=='e' && ch[1]=='6')
		in[i]=0xe6;
	  if(ch[0]=='e' && ch[1]=='7')
		in[i]=0xe7;
	  if(ch[0]=='e' && ch[1]=='8')
		in[i]=0xe8;
	  if(ch[0]=='e' && ch[1]=='9')
		in[i]=0xe9;
	  if(ch[0]=='e' && ch[1]=='a')
		in[i]=0xea;
	  if(ch[0]=='e' && ch[1]=='b')
		in[i]=0xeb;
	  if(ch[0]=='e' && ch[1]=='c')
		in[i]=0xec;
	  if(ch[0]=='e' && ch[1]=='d')
		in[i]=0xed;
	  if(ch[0]=='e' && ch[1]=='e')
		in[i]=0xee;
	  if(ch[0]=='e' && ch[1]=='f')
		in[i]=0xef;


	  if(ch[0]=='f' && ch[1]=='0')
		in[i]=0xf0;
	  if(ch[0]=='f' && ch[1]=='1')
		in[i]=0xf1;
	  if(ch[0]=='f' && ch[1]=='2')
		in[i]=0xf2;
	  if(ch[0]=='f' && ch[1]=='3')
		in[i]=0xf3;
	  if(ch[0]=='f' && ch[1]=='4')
		in[i]=0xf4;
	  if(ch[0]=='f' && ch[1]=='5')
		in[i]=0xf5;
	  if(ch[0]=='f' && ch[1]=='6')
		in[i]=0xf6;
	  if(ch[0]=='f' && ch[1]=='7')
		in[i]=0xf7;
	  if(ch[0]=='f' && ch[1]=='8')
		in[i]=0xf8;
	  if(ch[0]=='f' && ch[1]=='9')
		in[i]=0xf9;
	  if(ch[0]=='f' && ch[1]=='a')
		in[i]=0xfa;
	  if(ch[0]=='f' && ch[1]=='b')
		in[i]=0xfb;
	  if(ch[0]=='f' && ch[1]=='c')
		in[i]=0xfc;
	  if(ch[0]=='f' && ch[1]=='d')
		in[i]=0xfd;
	  if(ch[0]=='f' && ch[1]=='e')
		in[i]=0xfe;
	  if(ch[0]=='f' && ch[1]=='f')
		in[i]=0xff;
	}

	//The Key-Expansion routine must be called before the decryption routine.
	KeyExpansion();

	// The next function call decrypts the CipherText with the Key using AES algorithm.
	InvCipher();

	// Output the decrypted text.

	for(i=0;i<Nb*4;i++)
	{
		if (count1==0 && i==Nb*4-1)
			inttohex(fp2, out[i]);
		else
		{
			inttohex(fp2, out[i]);
			fp2<<" ";
		}
	}

	//if still some text is left again call the LABEL routine for next 16characters
	if (count1 > 0)
	goto LABEL ;

	//after completing the file operation close both the files
	fp1.close();
	fp2.close();

	ifstream fp3;
	ofstream fp4;

	fp3.open("c:/orig1.txt");
	fp4.open("c:/origt1.txt");
	int j;
	while (1)
	{
		if(fp3.eof())
			break;
		else
		{	int integ;
			char m[3],k;
			int n[2];
			fp3.get(m,3);
			for(j=0;j<=1;j++)
			{
				if(m[j]=='a')
					n[j]=10;
				else if(m[j]=='b')
					n[j]=11;
				else if(m[j]=='c')
					n[j]=12;
				else if(m[j]=='d')
					n[j]=13;
				else if(m[j]=='e')
					n[j]=14;
				else if(m[j]=='f')
					n[j]=15;
			else
					n[j]=(int)m[j]-'0';
			}
			integ=n[0]*16+n[1];

			//reading the blank space b/w two hex numbers
			fp3.get(k);
			
			//o/p the final decrypted to data a file
			fp4<<char(integ);
		}
	}

	//closing both the file after completing file operations

	fp3.close();
	fp4.close();
	//end time
	time (&end);
  	dif = difftime (end,start);

	//printing the time taken in encrytion
	cout<<"Time taken in DECRYPTION with parallelization is "<<dif<<" seconds\n";
	cout<<"Press any key to continue...";
	getchar();

	return 1;
}
