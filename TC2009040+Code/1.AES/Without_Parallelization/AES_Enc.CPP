/*
******************************************************************
**       Advanced Encryption Standard implementation in C++     **
**       By Anoop Singh & Ankit Malani                          **
******************************************************************
This is the source code for encryption using the latest AES algorithm.
AES algorithm is also called Rijndael algorithm. AES algorithm is
recommended for non-classified by the National Institute of Standards 
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
#include<time.h>
#include<stdio.h>
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

using namespace std;

int count=0;

// The number of rounds in AES Cipher. It is simply initiated to zero. The actual value is recieved in the program.
int Nr=0;

// The number of 32 bit words in the key. It is simply initiated to zero. The actual value is recieved in the program.
int Nk=0;

// in - it is the array that holds the plain text to be encrypted.
// out - it is the array that holds the key for encryption.
// state - the array that holds the intermediate results during encryption.
unsigned char in[16], out[16], state[4][4];

// The array that stores the round keys.
unsigned char RoundKey[240];

// The Key input to the AES Program
unsigned char Key[32];

void print(ofstream &, int);
void inttohex(ofstream &, int);
int getSBoxValue(int num)
{
	int sbox[256] =
	{
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	}; //F
	return sbox[num];
}


// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
// Note that i starts at 1, not 0).
// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
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
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to encrypt the states.
void KeyExpansion()
{
	int i,j;
	unsigned char temp[4],k;

	// The first round key is the key itself.
	for(i=0;i<Nk;i++)
	{
		RoundKey[i*4]=Key[i*4];
		RoundKey[i*4+1]=Key[i*4+1];
		RoundKey[i*4+2]=Key[i*4+2];
		RoundKey[i*4+3]=Key[i*4+3];
	}

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
	}//while
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
void SubBytes()
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[i][j] = getSBoxValue(state[i][j]);

		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows()
{
	unsigned char temp;

	// Rotate first row 1 columns to left
	temp=state[1][0];
	state[1][0]=state[1][1];
	state[1][1]=state[1][2];
	state[1][2]=state[1][3];
	state[1][3]=temp;

	// Rotate second row 2 columns to left	
	temp=state[2][0];
	state[2][0]=state[2][2];
	state[2][2]=temp;

	temp=state[2][1];
	state[2][1]=state[2][3];
	state[2][3]=temp;

	// Rotate third row 3 columns to left
	temp=state[3][0];
	state[3][0]=state[3][3];
	state[3][3]=state[3][2];
	state[3][2]=state[3][1];
	state[3][1]=temp;
}

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// MixColumns function mixes the columns of the state matrix
void MixColumns()
{
	int i;
	unsigned char Tmp,Tm,t;
	for(i=0;i<4;i++)
	{	
		t=state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ;
		Tm = state[0][i] ^ state[1][i] ; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp ;
		Tm = state[1][i] ^ state[2][i] ; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp ;
		Tm = state[2][i] ^ state[3][i] ; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp ;
		Tm = state[3][i] ^ t ; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp ;
	}
}

// Cipher is the main function that encrypts the PlainText.
void Cipher()
{
	int i,j,round=0;

	//Copy the input PlainText to state array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			state[j][i] = in[i*4 + j];
		}
	}

	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0); 
	
	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for(round=1;round<Nr;round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);

	// The encryption process is over.
	// Copy the state array to output array.
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			out[i*4+j]=state[j][i];
		}
	}
}

void convtohex()
{
	int num_char=0, charac;
	ifstream fp3;
	ofstream fp4;
	fp3.open("c:/text.txt");
	fp4.open("c:/input1.txt");

	char ch;

	fp3.get(ch);

	while (!fp3.eof())
	{
		num_char++;
		fp4 << "0x";
		
		inttohex(fp4, int(ch));
		
		fp3.get(ch);
	}
	charac=num_char;
	count=(num_char/16)+1;
	num_char=num_char/16;
	num_char=(16*(num_char+1))-charac;

	for (int i=0; i<num_char; i++)
	{
		if (i== num_char-1)
			fp4 << "0x20";
		else
			fp4 << "0x20 ";
	}
	
}

void inttohex(ofstream &o, int a)
{
	int b=16,d;
	if(a==0)
		o<<"00";
	if(a>0 && a<=15)
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

	o<<" ";
	return;
}

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
void main()
{
	//time variables
	time_t start,end;
	double dif;

	//start time
	time (&start);

	convtohex();
	ofstream fp2;
	ifstream fp1;
	fp2.open("c:/output1.txt");
	fp1.open("c:/input1.txt");
	int i;

Nr=128;

	// Calculate Nk and Nr from the recieved value.
LABEL:  count--;
	Nr=128;
	Nk = Nr / 32;
	Nr = Nk + 6;


	unsigned char temp[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};
	// Copy the Key
	for(i=0;i<Nk*4;i++)
	{
		Key[i]=temp[i];
	}

	//Clear the input buffer
//	_flushall();
	
	char ch[5], m;
	for(i=0;i<Nb*4;i++)
	{		
		fp1.get(ch, 5);
		fp1.get(m);
	  if(ch[2]=='0' && ch[3]=='0')
		in[i]=0x00;
	  if(ch[2]=='0' && ch[3]=='1')
		in[i]=0x01;
	  if(ch[2]=='0' && ch[3]=='2')
		in[i]=0x02;
	  if(ch[2]=='0' && ch[3]=='3')
		in[i]=0x03;
	  if(ch[2]=='0' && ch[3]=='4')
		in[i]=0x04;
	  if(ch[2]=='0' && ch[3]=='5')
		in[i]=0x05;
	  if(ch[2]=='0' && ch[3]=='6')
		in[i]=0x06;
	  if(ch[2]=='0' && ch[3]=='7')
		in[i]=0x07;
	  if(ch[2]=='0' && ch[3]=='8')
		in[i]=0x08;
	  if(ch[2]=='0' && ch[3]=='9')
		in[i]=0x09;
	  if(ch[2]=='0' && ch[3]=='a')
		in[i]=0x0a;
	  if(ch[2]=='0' && ch[3]=='b')
		in[i]=0x0b;
	  if(ch[2]=='0' && ch[3]=='c')
		in[i]=0x0c;
	  if(ch[2]=='0' && ch[3]=='d')
		in[i]=0x0d;
	  if(ch[2]=='0' && ch[3]=='e')
		in[i]=0x0e;
	  if(ch[2]=='0' && ch[3]=='f')
		in[i]=0x0f;


	  if(ch[2]=='1' && ch[3]=='0')
		in[i]=0x10;
	  if(ch[2]=='1' && ch[3]=='1')
		in[i]=0x11;
	  if(ch[2]=='1' && ch[3]=='2')
		in[i]=0x12;
	  if(ch[2]=='1' && ch[3]=='3')
		in[i]=0x13;
	  if(ch[2]=='1' && ch[3]=='4')
		in[i]=0x14;
	  if(ch[2]=='1' && ch[3]=='5')
		in[i]=0x15;
	  if(ch[2]=='1' && ch[3]=='6')
		in[i]=0x16;
	  if(ch[2]=='1' && ch[3]=='7')
		in[i]=0x17;
	  if(ch[2]=='1' && ch[3]=='8')
		in[i]=0x18;
	  if(ch[2]=='1' && ch[3]=='9')
		in[i]=0x19;
	  if(ch[2]=='1' && ch[3]=='a')
		in[i]=0x1a;
	  if(ch[2]=='1' && ch[3]=='b')
		in[i]=0x1b;
	  if(ch[2]=='1' && ch[3]=='c')
		in[i]=0x1c;
	  if(ch[2]=='1' && ch[3]=='d')
		in[i]=0x1d;
	  if(ch[2]=='1' && ch[3]=='e')
		in[i]=0x1e;
	  if(ch[2]=='1' && ch[3]=='f')
		in[i]=0x1f;

	  if(ch[2]=='2' && ch[3]=='0')
		in[i]=0x20;
	  if(ch[2]=='2' && ch[3]=='1')
		in[i]=0x21;
	  if(ch[2]=='2' && ch[3]=='2')
		in[i]=0x22;
	  if(ch[2]=='2' && ch[3]=='3')
		in[i]=0x23;
	  if(ch[2]=='2' && ch[3]=='4')
		in[i]=0x24;
	  if(ch[2]=='2' && ch[3]=='5')
		in[i]=0x25;
	  if(ch[2]=='2' && ch[3]=='6')
		in[i]=0x26;
	  if(ch[2]=='2' && ch[3]=='7')
		in[i]=0x27;
	  if(ch[2]=='2' && ch[3]=='8')
		in[i]=0x28;
	  if(ch[2]=='2' && ch[3]=='9')
		in[i]=0x29;
	  if(ch[2]=='2' && ch[3]=='a')
		in[i]=0x2a;
	  if(ch[2]=='2' && ch[3]=='b')
		in[i]=0x2b;
	  if(ch[2]=='2' && ch[3]=='c')
		in[i]=0x2c;
	  if(ch[2]=='2' && ch[3]=='d')
		in[i]=0x2d;
	  if(ch[2]=='2' && ch[3]=='e')
		in[i]=0x2e;
	  if(ch[2]=='2' && ch[3]=='f')
		in[i]=0x2f;

	  if(ch[2]=='3' && ch[3]=='0')
		in[i]=0x30;
	  if(ch[2]=='3' && ch[3]=='1')
		in[i]=0x31;
	  if(ch[2]=='3' && ch[3]=='2')
		in[i]=0x32;
	  if(ch[2]=='3' && ch[3]=='3')
		in[i]=0x33;
	  if(ch[2]=='3' && ch[3]=='4')
		in[i]=0x34;
	  if(ch[2]=='3' && ch[3]=='5')
		in[i]=0x35;
	  if(ch[2]=='3' && ch[3]=='6')
		in[i]=0x36;
	  if(ch[2]=='3' && ch[3]=='7')
		in[i]=0x37;
	  if(ch[2]=='3' && ch[3]=='8')
		in[i]=0x38;
	  if(ch[2]=='3' && ch[3]=='9')
		in[i]=0x39;
	  if(ch[2]=='3' && ch[3]=='a')
		in[i]=0x3a;
	  if(ch[2]=='3' && ch[3]=='b')
		in[i]=0x3b;
	  if(ch[2]=='3' && ch[3]=='c')
		in[i]=0x3c;
	  if(ch[2]=='3' && ch[3]=='d')
		in[i]=0x3d;
	  if(ch[2]=='3' && ch[3]=='e')
		in[i]=0x3e;
	  if(ch[2]=='3' && ch[3]=='f')
		in[i]=0x3f;

	  if(ch[2]=='4' && ch[3]=='0')
		in[i]=0x40;
	  if(ch[2]=='4' && ch[3]=='1')
		in[i]=0x41;
	  if(ch[2]=='4' && ch[3]=='2')
		in[i]=0x42;
	  if(ch[2]=='4' && ch[3]=='3')
		in[i]=0x43;
	  if(ch[2]=='4' && ch[3]=='4')
		in[i]=0x44;
	  if(ch[2]=='4' && ch[3]=='5')
		in[i]=0x45;
	  if(ch[2]=='4' && ch[3]=='6')
		in[i]=0x46;
	  if(ch[2]=='4' && ch[3]=='7')
		in[i]=0x47;
	  if(ch[2]=='4' && ch[3]=='8')
		in[i]=0x48;
	  if(ch[2]=='4' && ch[3]=='9')
		in[i]=0x49;
	  if(ch[2]=='4' && ch[3]=='a')
		in[i]=0x4a;
	  if(ch[2]=='4' && ch[3]=='b')
		in[i]=0x4b;
	  if(ch[2]=='4' && ch[3]=='c')
		in[i]=0x4c;
	  if(ch[2]=='4' && ch[3]=='d')
		in[i]=0x4d;
	  if(ch[2]=='4' && ch[3]=='e')
		in[i]=0x4e;
	  if(ch[2]=='4' && ch[3]=='f')
		in[i]=0x4f;

	  if(ch[2]=='5' && ch[3]=='0')
		in[i]=0x50;
	  if(ch[2]=='5' && ch[3]=='1')
		in[i]=0x51;
	  if(ch[2]=='5' && ch[3]=='2')
		in[i]=0x52;
	  if(ch[2]=='5' && ch[3]=='3')
		in[i]=0x53;
	  if(ch[2]=='5' && ch[3]=='4')
		in[i]=0x54;
	  if(ch[2]=='5' && ch[3]=='5')
		in[i]=0x55;
	  if(ch[2]=='5' && ch[3]=='6')
		in[i]=0x56;
	  if(ch[2]=='5' && ch[3]=='7')
		in[i]=0x57;
	  if(ch[2]=='5' && ch[3]=='8')
		in[i]=0x58;
	  if(ch[2]=='5' && ch[3]=='9')
		in[i]=0x59;
	  if(ch[2]=='5' && ch[3]=='a')
		in[i]=0x5a;
	  if(ch[2]=='5' && ch[3]=='b')
		in[i]=0x5b;
	  if(ch[2]=='5' && ch[3]=='c')
		in[i]=0x5c;
	  if(ch[2]=='5' && ch[3]=='d')
		in[i]=0x5d;
	  if(ch[2]=='5' && ch[3]=='e')
		in[i]=0x5e;
	  if(ch[2]=='5' && ch[3]=='f')
		in[i]=0x5f;

	  if(ch[2]=='6' && ch[3]=='0')
		in[i]=0x60;
	  if(ch[2]=='6' && ch[3]=='1')
		in[i]=0x61;
	  if(ch[2]=='6' && ch[3]=='2')
		in[i]=0x62;
	  if(ch[2]=='6' && ch[3]=='3')
		in[i]=0x63;
	  if(ch[2]=='6' && ch[3]=='4')
		in[i]=0x64;
	  if(ch[2]=='6' && ch[3]=='5')
		in[i]=0x65;
	  if(ch[2]=='6' && ch[3]=='6')
		in[i]=0x66;
	  if(ch[2]=='6' && ch[3]=='7')
		in[i]=0x67;
	  if(ch[2]=='6' && ch[3]=='8')
		in[i]=0x68;
	  if(ch[2]=='6' && ch[3]=='9')
		in[i]=0x69;
	  if(ch[2]=='6' && ch[3]=='a')
		in[i]=0x6a;
	  if(ch[2]=='6' && ch[3]=='b')
		in[i]=0x6b;
	  if(ch[2]=='6' && ch[3]=='c')
		in[i]=0x6c;
	  if(ch[2]=='6' && ch[3]=='d')
		in[i]=0x6d;
	  if(ch[2]=='6' && ch[3]=='e')
		in[i]=0x6e;
	  if(ch[2]=='6' && ch[3]=='f')
		in[i]=0x6f;

	  if(ch[2]=='7' && ch[3]=='0')
		in[i]=0x70;
	  if(ch[2]=='7' && ch[3]=='1')
		in[i]=0x71;
	  if(ch[2]=='7' && ch[3]=='2')
		in[i]=0x72;
	  if(ch[2]=='7' && ch[3]=='3')
		in[i]=0x73;
	  if(ch[2]=='7' && ch[3]=='4')
		in[i]=0x74;
	  if(ch[2]=='7' && ch[3]=='5')
		in[i]=0x75;
	  if(ch[2]=='7' && ch[3]=='6')
		in[i]=0x76;
	  if(ch[2]=='7' && ch[3]=='7')
		in[i]=0x77;
	  if(ch[2]=='7' && ch[3]=='8')
		in[i]=0x78;
	  if(ch[2]=='7' && ch[3]=='9')
		in[i]=0x79;
	  if(ch[2]=='7' && ch[3]=='a')
		in[i]=0x7a;
	  if(ch[2]=='7' && ch[3]=='b')
		in[i]=0x7b;
	  if(ch[2]=='7' && ch[3]=='c')
		in[i]=0x7c;
	  if(ch[2]=='7' && ch[3]=='d')
		in[i]=0x7d;
	  if(ch[2]=='7' && ch[3]=='e')
		in[i]=0x7e;
	  if(ch[2]=='7' && ch[3]=='f')
		in[i]=0x7f;

	  if(ch[2]=='8' && ch[3]=='0')
		in[i]=0x80;
	  if(ch[2]=='8' && ch[3]=='1')
		in[i]=0x81;
	  if(ch[2]=='8' && ch[3]=='2')
		in[i]=0x82;
	  if(ch[2]=='8' && ch[3]=='3')
		in[i]=0x83;
	  if(ch[2]=='8' && ch[3]=='4')
		in[i]=0x84;
	  if(ch[2]=='8' && ch[3]=='5')
		in[i]=0x85;
	  if(ch[2]=='8' && ch[3]=='6')
		in[i]=0x86;
	  if(ch[2]=='8' && ch[3]=='7')
		in[i]=0x87;
	  if(ch[2]=='8' && ch[3]=='8')
		in[i]=0x88;
	  if(ch[2]=='8' && ch[3]=='9')
		in[i]=0x89;
	  if(ch[2]=='8' && ch[3]=='a')
		in[i]=0x8a;
	  if(ch[2]=='8' && ch[3]=='b')
		in[i]=0x8b;
	  if(ch[2]=='8' && ch[3]=='c')
		in[i]=0x8c;
	  if(ch[2]=='8' && ch[3]=='d')
		in[i]=0x8d;
	  if(ch[2]=='8' && ch[3]=='e')
		in[i]=0x8e;
	  if(ch[2]=='8' && ch[3]=='f')
		in[i]=0x8f;


	  if(ch[2]=='9' && ch[3]=='0')
		in[i]=0x90;
	  if(ch[2]=='9' && ch[3]=='1')
		in[i]=0x91;
	  if(ch[2]=='9' && ch[3]=='2')
		in[i]=0x92;
	  if(ch[2]=='9' && ch[3]=='3')
		in[i]=0x93;
	  if(ch[2]=='9' && ch[3]=='4')
		in[i]=0x94;
	  if(ch[2]=='9' && ch[3]=='5')
		in[i]=0x95;
	  if(ch[2]=='9' && ch[3]=='6')
		in[i]=0x96;
	  if(ch[2]=='9' && ch[3]=='7')
		in[i]=0x97;
	  if(ch[2]=='9' && ch[3]=='8')
		in[i]=0x98;
	  if(ch[2]=='9' && ch[3]=='9')
		in[i]=0x99;
	  if(ch[2]=='9' && ch[3]=='a')
		in[i]=0x9a;
	  if(ch[2]=='9' && ch[3]=='b')
		in[i]=0x9b;
	  if(ch[2]=='9' && ch[3]=='c')
		in[i]=0x9c;
	  if(ch[2]=='9' && ch[3]=='d')
		in[i]=0x9d;
	  if(ch[2]=='9' && ch[3]=='e')
		in[i]=0x9e;
	  if(ch[2]=='9' && ch[3]=='f')
		in[i]=0x9f;


	  if(ch[2]=='a' && ch[3]=='0')
		in[i]=0xa0;
	  if(ch[2]=='a' && ch[3]=='1')
		in[i]=0xa1;
	  if(ch[2]=='a' && ch[3]=='2')
		in[i]=0xa2;
	  if(ch[2]=='a' && ch[3]=='3')
		in[i]=0xa3;
	  if(ch[2]=='a' && ch[3]=='4')
		in[i]=0xa4;
	  if(ch[2]=='a' && ch[3]=='5')
		in[i]=0xa5;
	  if(ch[2]=='a' && ch[3]=='6')
		in[i]=0xa6;
	  if(ch[2]=='a' && ch[3]=='7')
		in[i]=0xa7;
	  if(ch[2]=='a' && ch[3]=='8')
		in[i]=0xa8;
	  if(ch[2]=='a' && ch[3]=='9')
		in[i]=0xa9;
	  if(ch[2]=='a' && ch[3]=='a')
		in[i]=0xaa;
	  if(ch[2]=='a' && ch[3]=='b')
		in[i]=0xab;
	  if(ch[2]=='a' && ch[3]=='c')
		in[i]=0xac;
	  if(ch[2]=='a' && ch[3]=='d')
		in[i]=0xad;
	  if(ch[2]=='a' && ch[3]=='e')
		in[i]=0xae;
	  if(ch[2]=='a' && ch[3]=='f')
		in[i]=0xaf;


	  if(ch[2]=='b' && ch[3]=='0')
		in[i]=0xb0;
	  if(ch[2]=='b' && ch[3]=='1')
		in[i]=0xb1;
	  if(ch[2]=='b' && ch[3]=='2')
		in[i]=0xb2;
	  if(ch[2]=='b' && ch[3]=='3')
		in[i]=0xb3;
	  if(ch[2]=='b' && ch[3]=='4')
		in[i]=0xb4;
	  if(ch[2]=='b' && ch[3]=='5')
		in[i]=0xb5;
	  if(ch[2]=='b' && ch[3]=='6')
		in[i]=0xb6;
	  if(ch[2]=='b' && ch[3]=='7')
		in[i]=0xb7;
	  if(ch[2]=='b' && ch[3]=='8')
		in[i]=0xb8;
	  if(ch[2]=='b' && ch[3]=='9')
		in[i]=0xb9;
	  if(ch[2]=='b' && ch[3]=='a')
		in[i]=0xba;
	  if(ch[2]=='b' && ch[3]=='b')
		in[i]=0xbb;
	  if(ch[2]=='b' && ch[3]=='c')
		in[i]=0xbc;
	  if(ch[2]=='b' && ch[3]=='d')
		in[i]=0xbd;
	  if(ch[2]=='b' && ch[3]=='e')
		in[i]=0xbe;
	  if(ch[2]=='b' && ch[3]=='f')
		in[i]=0xbf;


	  if(ch[2]=='c' && ch[3]=='0')
		in[i]=0xc0;
	  if(ch[2]=='c' && ch[3]=='1')
		in[i]=0xc1;
	  if(ch[2]=='c' && ch[3]=='2')
		in[i]=0xc2;
	  if(ch[2]=='c' && ch[3]=='3')
		in[i]=0xc3;
	  if(ch[2]=='c' && ch[3]=='4')
		in[i]=0xc4;
	  if(ch[2]=='c' && ch[3]=='5')
		in[i]=0xc5;
	  if(ch[2]=='c' && ch[3]=='6')
		in[i]=0xc6;
	  if(ch[2]=='c' && ch[3]=='7')
		in[i]=0xc7;
	  if(ch[2]=='c' && ch[3]=='8')
		in[i]=0xc8;
	  if(ch[2]=='c' && ch[3]=='9')
		in[i]=0xc9;
	  if(ch[2]=='c' && ch[3]=='a')
		in[i]=0xca;
	  if(ch[2]=='c' && ch[3]=='b')
		in[i]=0xcb;
	  if(ch[2]=='c' && ch[3]=='c')
		in[i]=0xcc;
	  if(ch[2]=='c' && ch[3]=='d')
		in[i]=0xcd;
	  if(ch[2]=='c' && ch[3]=='e')
		in[i]=0xce;
	  if(ch[2]=='c' && ch[3]=='f')
		in[i]=0xcf;


	  if(ch[2]=='d' && ch[3]=='0')
		in[i]=0xd0;
	  if(ch[2]=='d' && ch[3]=='1')
		in[i]=0xd1;
	  if(ch[2]=='d' && ch[3]=='2')
		in[i]=0xd2;
	  if(ch[2]=='d' && ch[3]=='3')
		in[i]=0xd3;
	  if(ch[2]=='d' && ch[3]=='4')
		in[i]=0xd4;
	  if(ch[2]=='d' && ch[3]=='5')
		in[i]=0xd5;
	  if(ch[2]=='d' && ch[3]=='6')
		in[i]=0xd6;
	  if(ch[2]=='d' && ch[3]=='7')
		in[i]=0xd7;
	  if(ch[2]=='d' && ch[3]=='8')
		in[i]=0xd8;
	  if(ch[2]=='d' && ch[3]=='9')
		in[i]=0xd9;
	  if(ch[2]=='d' && ch[3]=='a')
		in[i]=0xda;
	  if(ch[2]=='d' && ch[3]=='b')
		in[i]=0xdb;
	  if(ch[2]=='d' && ch[3]=='c')
		in[i]=0xdc;
	  if(ch[2]=='d' && ch[3]=='d')
		in[i]=0xdd;
	  if(ch[2]=='d' && ch[3]=='e')
		in[i]=0xde;
	  if(ch[2]=='d' && ch[3]=='f')
		in[i]=0xdf;


	  if(ch[2]=='e' && ch[3]=='0')
		in[i]=0xe0;
	  if(ch[2]=='e' && ch[3]=='1')
		in[i]=0xe1;
	  if(ch[2]=='e' && ch[3]=='2')
		in[i]=0xe2;
	  if(ch[2]=='e' && ch[3]=='3')
		in[i]=0xe3;
	  if(ch[2]=='e' && ch[3]=='4')
		in[i]=0xe4;
	  if(ch[2]=='e' && ch[3]=='5')
		in[i]=0xe5;
	  if(ch[2]=='e' && ch[3]=='6')
		in[i]=0xe6;
	  if(ch[2]=='e' && ch[3]=='7')
		in[i]=0xe7;
	  if(ch[2]=='e' && ch[3]=='8')
		in[i]=0xe8;
	  if(ch[2]=='e' && ch[3]=='9')
		in[i]=0xe9;
	  if(ch[2]=='e' && ch[3]=='a')
		in[i]=0xea;
	  if(ch[2]=='e' && ch[3]=='b')
		in[i]=0xeb;
	  if(ch[2]=='e' && ch[3]=='c')
		in[i]=0xec;
	  if(ch[2]=='e' && ch[3]=='d')
		in[i]=0xed;
	  if(ch[2]=='e' && ch[3]=='e')
		in[i]=0xee;
	  if(ch[2]=='e' && ch[3]=='f')
		in[i]=0xef;


	  if(ch[2]=='f' && ch[3]=='0')
		in[i]=0xf0;
	  if(ch[2]=='f' && ch[3]=='1')
		in[i]=0xf1;
	  if(ch[2]=='f' && ch[3]=='2')
		in[i]=0xf2;
	  if(ch[2]=='f' && ch[3]=='3')
		in[i]=0xf3;
	  if(ch[2]=='f' && ch[3]=='4')
		in[i]=0xf4;
	  if(ch[2]=='f' && ch[3]=='5')
		in[i]=0xf5;
	  if(ch[2]=='f' && ch[3]=='6')
		in[i]=0xf6;
	  if(ch[2]=='f' && ch[3]=='7')
		in[i]=0xf7;
	  if(ch[2]=='f' && ch[3]=='8')
		in[i]=0xf8;
	  if(ch[2]=='f' && ch[3]=='9')
		in[i]=0xf9;
	  if(ch[2]=='f' && ch[3]=='a')
		in[i]=0xfa;
	  if(ch[2]=='f' && ch[3]=='b')
		in[i]=0xfb;
	  if(ch[2]=='f' && ch[3]=='c')
		in[i]=0xfc;
	  if(ch[2]=='f' && ch[3]=='d')
		in[i]=0xfd;
	  if(ch[2]=='f' && ch[3]=='e')
		in[i]=0xfe;
	  if(ch[2]=='f' && ch[3]=='f')
		in[i]=0xff;

	//  if(i==1 && count==0)
	//	  cin>>in[i];
	
	}
	
	
	// The KeyExpansion routine must be called before encryption.
	KeyExpansion();

	// The next function call encrypts the PlainText with the Key using AES algorithm.
	Cipher();

	// Output the encrypted text.

	for(i=0;i<Nk*4;i++)
	{
		if (count==0 && i==Nk*4-1)
		{
			inttohex(fp2, out[i]);
		}
		else
		{
			
			inttohex(fp2, out[i]);
			//fp2<<" ";
		}
	}


	if (count > 0)
		goto LABEL ;

	fp1.close();
	fp2.close();
	//end time
	time (&end);
  	dif = difftime (end,start);

	//printing the time taken in encrytion
	cout<<"Time taken in ENCRYPTION without parallelization is "<<dif<<" seconds\n";
	cout<<"Press any key to continue...";
	getchar();


}