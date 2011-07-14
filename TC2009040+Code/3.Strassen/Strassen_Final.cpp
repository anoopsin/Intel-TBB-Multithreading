 //matrix multiplication

#include<iostream>
#include<conio.h>
#include "tbb/tick_count.h"
#include "tbb/task_scheduler_init.h"
#include "tbb/parallel_for.h"
#include "tbb/blocked_range.h"
#include <time.h>
#include "tbb/blocked_range2d.h"
#include "tbb/blocked_range3d.h"

using namespace std;
using namespace tbb;

const size_t L = 2;
const size_t M = 2;
const size_t N = 2;

int matrix_A[4][4]={0};
int matrix_B[4][4]={0};
int matrix_C[4][4]={0};

void get_matrix_A( );
void get_matrix_B( );
void multiply_matrices( );
void show_matrix_C( );

void add_2x2_matrices(const int [2][2],const int [2][2],int [2][2]);
void subtract_2x2_matrices(const int [2][2],const int [2][2],int [2][2]);
void multiply_2x2_matrices(const int [2][2],const int [2][2],int [2][2]);

 
class Addition {
    int (*my_a)[L];
    int (*my_b)[N];
    int (*my_c)[N];
public:
    void operator()
	(const blocked_range2d<size_t>& r )
	const {
        int (*a)[L] = my_a; // a,b,c used in example to emphasize
        int (*b)[N] = my_b; // commonality with serial code
        int (*c)[N] = my_c;
        for( size_t i=r.rows().begin(); i!=r.rows().end(); ++i )
		{
            for( size_t j=r.cols().begin(); j!=r.cols().end(); ++j )
			{
				 c[i][j]=(a[i][j]+b[i][j]);
			}
		}
		}
    
Addition( int a[M][L], int b[L][N], int c[M][N] ) :  my_a(a), my_b(b), my_c(c)  {}
};

class Subtraction {
    int (*my_a)[L];
    int (*my_b)[N];
    int (*my_c)[N];
public:
    void operator()
	(const blocked_range2d<size_t>& r )
	const {
        int (*a)[L] = my_a; // a,b,c used in example to emphasize
        int (*b)[N] = my_b; // commonality with serial code
        int (*c)[N] = my_c;
        for( size_t i=r.rows().begin(); i!=r.rows().end(); ++i )
		{
            for( size_t j=r.cols().begin(); j!=r.cols().end(); ++j )
			{
				 c[i][j]=(a[i][j]-b[i][j]);
			}
		}
		}
    
Subtraction( int a[M][L], int b[L][N], int c[M][N] ) :  my_a(a), my_b(b), my_c(c)  {}
};

class Multiplication {
    int (*my_a)[L];
    int (*my_b)[N];
    int (*my_c)[N];
public:
    void operator()
	(const blocked_range3d<size_t>& r )
	const {
        int (*a)[L] = my_a; // a,b,c used in example to emphasize
        int (*b)[N] = my_b; // commonality with serial code
        int (*c)[N] = my_c;
    for( size_t i=r.rows().begin(); i!=r.rows().end(); ++i )
	{
             for( size_t j=r.cols().begin(); j!=r.cols().end(); ++j )
       {
		  c[i][j]=0;
		         for( size_t k=r.cols().begin(); k!=r.cols().end(); ++k )
			  c[i][j]+=(a[j][k]*b[k][j]);
       }
    }	}
    
Multiplication( int a[M][L], int b[L][N], int c[M][N] ) :  my_a(a), my_b(b), my_c(c)  {}
};

int main( )
 {
    task_scheduler_init init;

    get_matrix_A( );
    get_matrix_B( );
	
	tbb::tick_count start = tbb::tick_count::now ();
    
	multiply_matrices( );

	tbb::tick_count stopclk = tbb::tick_count::now ();

    show_matrix_C( );
	std::cerr << "\nTime Taken: " <<(stopclk-start).seconds () << " seconds" << std::endl;
    cout<<"\n\n\n\n\n Press any key to exit...";
	int inp;
	cin>>inp;
    return 0;
 }

 
 void get_matrix_A( )
 {
    cout<<" Enter the values of Matrix-A row by row :\n "<<endl;
    cout<<" A  = "<<endl;

	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			cin>>matrix_A[i][j];
 }

 void get_matrix_B( )
 {
    cout<<" Enter the values of Matrix-B row by row :\n "<<endl;
    cout<<" B  = "<<endl;

	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			cin>>matrix_B[i][j];
 }

 
 void add_2x2_matrices(int a[2][2],int b[2][2],int c[2][2])
 {
    	parallel_for( blocked_range2d<size_t>(0, M, 2, 0, N, 2),Addition(a,b,c), auto_partitioner());
 }

 void subtract_2x2_matrices(int a[2][2],int b[2][2],int c[2][2])
 {
  parallel_for( blocked_range2d<size_t>(0, M, 2, 0, N, 2),Subtraction(a,b,c), auto_partitioner());
 }

 void multiply_2x2_matrices(int a[2][2],int b[2][2],int c[2][2])
 {
	 parallel_for( blocked_range3d<size_t>(0,L,2,0,M,2,0,N,2),Multiplication(a,b,c), auto_partitioner());
    
 }

  void multiply_2x2_matrices(const int a[2][2],const int b[2][2],int c[2][2])
 {
    for(int i=0;i<2;i++)		//PARALLELIZE
    {
       for(int j=0;j<2;j++)
       {
		  c[i][j]=0;
		  for(int k=0;k<2;k++)
			  c[i][j]+=(a[j][k]*b[k][j]);
       }
    }
 }
 void multiply_matrices( )
 {
    int A11[2][2]={0};
    int A12[2][2]={0};
    int A21[2][2]={0};
    int A22[2][2]={0};

    int B11[2][2]={0};
    int B12[2][2]={0};
    int B21[2][2]={0};
    int B22[2][2]={0};

    int C11[2][2]={0};
    int C12[2][2]={0};
    int C21[2][2]={0};
    int C22[2][2]={0};

    int i;
    int j;

    for(i=0;i<2;i++)
    {
       for(j=0;j<2;j++)
       {
	  A11[i][j]=matrix_A[i][j];
	  B11[i][j]=matrix_B[i][j];
       }
    }

    for(i=0;i<2;i++)
    {
       for(j=2;j<4;j++)
       {
	  A12[i][(j-2)]=matrix_A[i][j];
	  B12[i][(j-2)]=matrix_B[i][j];
       }
    }

    for(i=2;i<4;i++)
    {
       for(j=0;j<2;j++)
       {
	  A21[(i-2)][j]=matrix_A[i][j];
	  B21[(i-2)][j]=matrix_B[i][j];
       }
    }

    for(i=2;i<4;i++)
    {
       for(j=2;j<4;j++)
       {
	  A22[(i-2)][(j-2)]=matrix_A[i][j];
	  B22[(i-2)][(j-2)]=matrix_B[i][j];
       }
    }

    int M1[2][2]={0};
    int M2[2][2]={0};
    int M3[2][2]={0};
    int M4[2][2]={0};
    int M5[2][2]={0};
    int M6[2][2]={0};
    int M7[2][2]={0};

    int Temp1[2][2]={0};
    int Temp2[2][2]={0};

    subtract_2x2_matrices(A12,A22,Temp1);
    add_2x2_matrices(B21,B22,Temp2);
    multiply_2x2_matrices(Temp1,Temp2,M1);

    add_2x2_matrices(A11,A22,Temp1);
    add_2x2_matrices(B11,B22,Temp2);
    multiply_2x2_matrices(Temp1,Temp2,M2);

    subtract_2x2_matrices(A11,A21,Temp1);
    add_2x2_matrices(B11,B12,Temp2);
    multiply_2x2_matrices(Temp1,Temp2,M3);

    add_2x2_matrices(A11,A12,Temp1);
    multiply_2x2_matrices(Temp1,B22,M4);

    subtract_2x2_matrices(B12,B22,Temp1);
    multiply_2x2_matrices(Temp1,A11,M5);

    subtract_2x2_matrices(B21,B11,Temp1);
    multiply_2x2_matrices(Temp1,A22,M6);

    add_2x2_matrices(A21,A22,Temp1);
    multiply_2x2_matrices(Temp1,B11,M7);

    add_2x2_matrices(M1,M6,Temp1);
    subtract_2x2_matrices(M2,M4,Temp2);
    add_2x2_matrices(Temp1,Temp2,C11);

    add_2x2_matrices(M4,M5,C12);

    add_2x2_matrices(M6,M7,C21);

    subtract_2x2_matrices(M2,M3,Temp1);
    subtract_2x2_matrices(M5,M7,Temp2);
    add_2x2_matrices(Temp1,Temp2,C22);

    for(i=0;i<2;i++)
    {
       for(j=0;j<2;j++)
	  matrix_C[i][j]=C11[i][j];
    }

    for(i=0;i<2;i++)
    {
       for(j=2;j<4;j++)
	  matrix_C[i][j]=C12[i][(j-2)];
    }

    for(i=2;i<4;i++)
    {
       for(j=0;j<2;j++)
	  matrix_C[i][j]=C21[(i-2)][j];
    }

    for(i=2;i<4;i++)
    {
       for(j=2;j<4;j++)
	  matrix_C[i][j]=C22[(i-2)][(j-2)];
    }
 }

 void show_matrix_C( )
 {
    cout<<"\n\nValues of Matrix-C row by row :\n "<<endl;
    cout<<" C  = "<<endl;

    for(int i=0;i<4;i++)
	{
		for(int j=0;j<4;j++)
			cout<<matrix_C[i][j]<<"\t";
		cout<<"\n";
	}
 }