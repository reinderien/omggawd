#include <assert.h>
#include <pgapack-mpi/pgapack.h>

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
	
	int index;
	MPI_Comm_rank(MPI_COMM_WORLD, &index);
	
	b64_out(randrand, index);
	double fitness = stomp(index);
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

