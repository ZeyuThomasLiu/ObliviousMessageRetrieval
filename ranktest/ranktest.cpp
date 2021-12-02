#include <iostream>
#include <Eigen/Dense>
#include <time.h>
#include <random>
#include <NTL/BasicThreadPool.h>
 
using namespace Eigen;
using namespace std;

typedef Matrix<double, Dynamic, Dynamic> MatrixXI;

// This is to perform SRLC2 test
int test()
{

  int numthread = 1; // please use single thread here and make it multi-threaded externally
  NTL::SetNumThreads(numthread);
  int k = 50;
  int c = 5;
  int m = 2*k;
  int rounds = (1<<25)/numthread;

  std::random_device rd; // obtain a random number from hardware
  std::mt19937 gen(rd()); // seed the generator
  std::uniform_int_distribution<> distr(0, m-1); // define the range
  // rng_type::result_type const seedval = get_seed();

  NTL_EXEC_INDEX(numthread, index)
    int supercounter = rounds;
    int errorctr = 0;
  while(supercounter > 0){
    
    if(supercounter % (1<<12) == 0) cout << index << ": " << supercounter << endl;
  	MatrixXI mtx(m,k); 
    for(int i = 0; i < k; i++){
	    for(int j = 0; j < 3;){
	    	int bkt = distr(gen);
	    	if(mtx(bkt,i) == 0){
	    		mtx(bkt, i) = rand()%65537+1;
	    		j++;
	    		}
	    	}

	    }
  supercounter--;
  if(mtx.colPivHouseholderQr().rank() < k) {errorctr += 1; cout << "\n!!!\n" << endl; 
  if (errorctr>= 1) break;}

  for(int i = 0; i < m;i++){
    for(int j = 0; j < k; j++){
      mtx(i,j) = 0;
    }
  }
  }
  std::cout << rounds-supercounter << " " << errorctr << std::endl;
  NTL_EXEC_INDEX_END

  
	return 0;
}

int main(){
  test();
}
