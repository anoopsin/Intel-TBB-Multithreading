

#include<iostream>
#include<fstream>
#include<ios>
#include<iomanip>
#include<algorithm>
#include "tbb/task_scheduler_init.h"
#include "tbb/parallel_for.h"
#include "tbb/blocked_range.h"

using namespace std;
using namespace tbb;

class Convhex
{
	int num_c;
	char ch[5];
	char m;
	ofstream &a;
public:
	void operator()(const blocked_range<size_t>& r)
	const{
			for(size_t i=r.begin();i!=r.end();++i)
			{
					if (i== num_c - 1)
						a<<"0x20";
					else
						a<<"0x20 ";
			}//for
			}//const
		
	Convhex(ofstream &o, int num_ch) : a(o), num_c(num_ch) {};

			
};
