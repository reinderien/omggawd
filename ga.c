/*
Genetic Algorithm WTF Decisionator
(c) Greg Toombs 2013 (should I really put my name on this?)
*/

#include <assert.h>
#include <pgapack-mpi/pgapack.h>
#include <stdio.h>

void b64_out(int (*dorand)(), int index);
double stomp(int index);

int seed, m, b;

static int randrand() {
	seed = m*seed + b;
	return seed & 0xFFFFFF;
}

static double evaluate(PGAContext *pga, int p, int pop) {
	// int len = PGAGetStringLength(pga);
	
	m    = PGAGetIntegerAllele(pga, p, pop, 0),
	b    = PGAGetIntegerAllele(pga, p, pop, 1);
	seed = PGAGetIntegerAllele(pga, p, pop, 2);
	
	int core;
	MPI_Comm_rank(MPI_COMM_WORLD, &core);
	
	b64_out(randrand, core);
	double fitness = stomp(core);
	
	printf("core %d pop %d string %d score %5.2lf%%\n",
		core, pop, p, fitness*100);
	fflush(stdout);
	
	return fitness;
}

void ga(int *argc, char **argv) {
	MPI_Init(argc, &argv);

	#define ncoords 3
	PGAContext *pga = PGACreate(argc, argv,
		PGA_DATATYPE_INTEGER, ncoords, PGA_MAXIMIZE);
	assert(pga);
	
	int l[ncoords] = { 0, 0, 0 },
	    u[ncoords] = { 0xFFFFFF, 0xFFFFFF, 0xFFFFFF };
	PGASetIntegerInitRange(pga, l, u);
	PGASetMaxGAIterValue(pga, 100);
	PGASetUp(pga);
	PGARun(pga, evaluate);
	PGADestroy(pga);
	
	MPI_Finalize();
}

