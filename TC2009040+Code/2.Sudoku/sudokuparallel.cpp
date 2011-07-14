/*SUDOKU*/

#include <dos.h>
#include "tbb/tick_count.h"
#include "tbb/task_scheduler_init.h"
#include "tbb/parallel_for.h"
#include "tbb/blocked_range.h"
#include <time.h>
#include <iostream>
using namespace std;
using namespace tbb;

tbb::tick_count start,stopclk;

// sudoku elements, insert 0 for blank

int k[9][9],K[9][9]={
			{0,0,1,0,0,6,0,2,9},
			{0,0,0,0,0,8,0,0,0},
			{0,0,9,3,2,0,0,8,0},
			{0,0,0,0,0,2,0,0,7},
			{0,0,2,5,0,4,1,0,0},
			{4,0,0,9,0,0,0,0,0},
			{0,6,0,0,4,3,9,0,0},
			{0,0,0,7,0,0,0,0,0},
			{5,3,0,2,0,0,8,0,0}
};
int i,j,i1,j1,i2,j2;
int error,temp;
int count=0;

class Sudokui
{
	
	int m;
public:
	//Overloaded () Operator
	void operator()(const blocked_range<size_t>& r)
		const{
			for(size_t I=r.begin();I!=r.end();++I)
			{
				if(i!=I&&k[i][j]==k[I][j])
				{	error=1;
					break;
				}
			}

			}

	Sudokui(int n) : m(n) {};
};


class Sudokuj
{
	
	int m;
public:
	//Overloaded () Operator
	void operator()(const blocked_range<size_t>& r)
		const{
			for(size_t I=r.begin();I!=r.end();++I)
			{
				if(j!=I&&k[i][j]==k[i][I])
				{
					error=1;
					break;
				}
			}

			}
	Sudokuj(int n) : m(n) {};
};


// copy elements to another array
class Assign
{
	int i;
public:
	//Overloaded () Operator
	void operator()(const blocked_range<size_t>& r)
		const{
			for(size_t I=r.begin();I!=r.end();++I)
			{
				k[i][I]=K[i][I];
			}
			}
		Assign(int n) : i(n) {};
};


int main()
{
	task_scheduler_init init;

	// parallel_for call to copy array elements
	for(i=0;i<9;i++)
		parallel_for(blocked_range<size_t>(0, 9),Assign(i), auto_partitioner());
		
	goto matrixvalidation;

// update contents of matrix
matrixupdation:
	while(1)
	{
		cout<<"\n\nEnter Row, Col, Revised number:(0 to continue) ";
		cin>>i;
		if(i==0)break;
		cin>>j>>temp;
		if(i>0&&j>0&&temp>=0&&i<10&&j<10&&temp<10)
		{
			K[i-1][j-1]=temp;
			k[i-1][j-1]=temp;
		}
		else
			cout<<"\n\nEnter row/column 1 to 9 & number 0 to 9 only.";
	}

//check if contents of sudoku are valid
matrixvalidation:
	cout<<"Input matrix:";
	for(i=0;i<9;i++)
	{
		cout<<"\n";
		for(j=0;j<9;j++)
			cout<<k[i][j]<<" ";
	}

	for(i=0;i<9;i++)
	for(j=0;j<9;j++)
		if(k[i][j]<0||k[i][j]>9)
		{
			cout<<""<<i+1<<" "<<j+1<<" "<<k[i][j];
			cout<<"\n\nInput matrix error.";
			cout<<"\n\nNumbers should be 1 to 9 only.";
			goto matrixupdation;
		}

	for(i=0;i<9;i++)
	for(j=0;j<9;j++)
	{
		if(k[i][j]==0)continue;
		error=0;
		for(i1=0;i1<9;i1++)
			if(i!=i1&&k[i][j]==k[i1][j])
			{
				error=1;
				i2=i1;
				j2=j;
			}
		for(j1=0;j1<9;j1++)
			if(j!=j1&&k[i][j]==k[i][j1])
			{
				error=1;
				i2=i;
				j2=j1;
			}
		for(i1=0;i1<9;i1++)
		for(j1=0;j1<9;j1++)
			if((i!=i1||j!=j1)&&i/3==i1/3&&j/3==j1/3&&k[i][j]==k[i1][j1])
			{
				error=1;
				i2=i1;
				j2=j1;
			}
		if(error)
		{
			cout<<""<<i+1<<" "<<j+1<<" "<<k[i][j];
			cout<<""<<i2+1<<" "<<j2+1<<" "<<k[i2][j2];
			cout<<"Input matrix error.";
			cout<<"A number has been repeated in the same row, col or block";
			goto matrixupdation;
		}
	}

	
	
// Logic starts

	//time starts
	start = tbb::tick_count::now ();

	for(i=0;i<9;i++)
	for(j=0;j<9;j++)
	{
		if(K[i][j]>0) goto chksol;
		
		for(k[i][j]++;k[i][j]<=9;k[i][j]++)
		{
			error=0;

		//parallel_for call
			parallel_for(blocked_range<size_t>(0, 9,16),Sudokui(1));

			parallel_for(blocked_range<size_t>(0, 9,16),Sudokuj(1));

			for(i1=0;i1<9;i1++)
			for(j1=0;j1<9;j1++)
				if((i!=i1||j!=j1)&&i/3==i1/3&&j/3==j1/3&&k[i][j]==k[i1][j1])
					error=1;
			if(error==0)break;
		}
		
		if(k[i][j]>9)
		{
			k[i][j]=0;
			do
			{
				if(i==0&&j==0)goto nomoresol;
				if(j>0)j--;else{j=8;i--;}
			}while(K[i][j]>0);
			j--;
		}
		
		//time ends
		stopclk = tbb::tick_count::now ();

//display upto 50 solutions
chksol:	if(i==8&&j==8)
		{
			cout<<"\n\nSolution: "<<++count<<"\n\n";
			for(i1=0;i1<9;i1++)
			{
				for(j1=0;j1<9;j1++)
					cout<<k[i1][j1]<<" ";
				cout<<"\n";
			}
			if(count==50)
			{
				cout<<"Too many solutions.Not checking for more solutions.";
				return 1;
			}

			while(K[i][j]>0)
			{
				if(i==0&&j==0)goto nomoresol;
				if(j>0)j--;else{j=8;i--;}
			}
			k[i][j]=0;
			do
			{
				if(i==0&&j==0)goto nomoresol;
				if(j>0)j--;else{j=8;i--;}
			}while(K[i][j]>0);
			j--;
		}
	}

//display msg when finding sol is over
nomoresol:
	if(count>0)
		cout<<"\nNo more solutions possible\n";
	else
		cout<<"No solution.";

	std::cerr << "\nTime Taken: " <<(stopclk-start).seconds () << " seconds" << std::endl;
	
	//press key to exit
	char ch;
	ch=getchar();
	return 1;
}
