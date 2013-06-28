/*
Genetic Algorithm WTF Decisionator
(c) Greg Toombs 2013 (should I really put my name on this?)
*/

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pgapack-mpi/pgapack.h>
#include <stdio.h>
#include <unistd.h>

void b64_out(int (*dorand)(), int index);
double stomp(int index);

char **plines = 0;
int nlines = 0;

double readbest() {
	int fd = open("best.bin", O_RDONLY);
	double best;
	assert(sizeof(best) == read(fd, &best, sizeof(best)));
	close(fd);
	return best;
}

void writebest(double best) {
	int fd = open("best.bin", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	write(fd, &best, sizeof(best));
	close(fd);
}
	

static double evaluate(PGAContext *pga, int p, int pop) {
	// int nlines = PGAGetStringLength(pga);
	
	int *order = malloc(nlines * sizeof(int));
	for (int i = 0; i < nlines; i++) {
		order[i] = PGAGetIntegerAllele(pga, p, pop, i);
	}
	int *use = malloc(nlines * sizeof(int));
	for (int i = 0; i < nlines; i++) {
		use[i] = PGAGetIntegerAllele(pga, p, pop, i + nlines);
	}
	
	int core;
	MPI_Comm_rank(MPI_COMM_WORLD, &core);
	
	char filename[1024];
	snprintf(filename, sizeof(filename), "awesome-%d.c", core);
	FILE *source = fopen(filename, "w");
	fputs("int x = -1;\n"
		"int awesomerand() {\n",
		source);
	for (int iorder = 0; iorder < nlines; iorder++) {
		for (int i = 0; i < nlines; i++) {
			if (use[i] && order[i] == iorder)
				fputs(plines[i], source);
		}
	}
	fputs(
		"return x;\n"
		"}\n", source);
	fclose(source);
	snprintf(filename, sizeof(filename),
		"gcc -o libawesome-%d.so awesome-%d.c -fpic -shared -nostdinc -nostdlib 2>/dev/null",
		core, core);
	//                        ^^^^^^^^^^	
	
	int result = system(filename);
	if (result) return -1; // the stupid thing didn't compile. not so awesome.
	
	snprintf(filename, sizeof(filename), "./libawesome-%d.so", core);
	void *lib = dlopen(filename, RTLD_NOW);
	assert(lib);
	int (*awesomerand)() = dlsym(lib, "awesomerand");
	assert(awesomerand);
	
	b64_out(awesomerand, core);
		
	double fitness = stomp(core);
	
	printf("core %d pop %d string %d score %5.2lf%%\n",
		core, pop, p, fitness*100);
	fflush(stdout);
	
	if (readbest() < fitness) {
		writebest(fitness);
		printf("Found better algo with fitness = %f\n", fitness);
		fflush(stdout);
		
		FILE *resultsjs = fopen("results.js", "w");
		assert(resultsjs);
		fprintf(resultsjs, "var fitness = %f;\n", fitness);
		fprintf(resultsjs, "var awesome = new Array(");
		for (int i = 0; i < 100; i++) {
			fprintf(resultsjs, "%d", awesomerand());
			if (i < 99)
				fputc(',', resultsjs);
		}
		fputs(");", resultsjs);
		fclose(resultsjs);
	}

	dlclose(lib);
	
	return fitness;
}

int heatdeathoftheuniverse = 99999;

int main(int argc, char **argv) {
	// Number of coordinates = number of potentials
	// Lower and upper bounds are also the number of potentials, since
	// they determine the order of the statements that are written to awesome.
	
	writebest(-1);
	
	FILE *potentials = fopen("potentials.c", "r");
	plines = malloc(sizeof(char*));
	for (;;) {
		int nbuffer = 1024;
		char *buffer = malloc(nbuffer);
		if (!fgets(buffer, nbuffer, potentials)) {
			free(buffer);
			break;
		}
		nlines++;
		plines = realloc(plines, nlines*sizeof(char*));
		assert(plines);
		plines[nlines - 1] = buffer;
	}
	fclose(potentials);

	MPI_Init(&argc, &argv);

	PGAContext *pga = PGACreate(&argc, argv,
		PGA_DATATYPE_INTEGER, 2*nlines, PGA_MAXIMIZE);
	assert(pga);
	
	int *l = malloc(2*nlines * sizeof(int)),
		*u = malloc(2*nlines * sizeof(int));
	for (int i = 0; i < nlines; i++) {
		l[i] = 0;
		u[i] = nlines - 1;
		l[i + nlines] = 0;
		u[i + nlines] = 1;
	}
	PGASetIntegerInitRange(pga, l, u);
	PGASetMaxGAIterValue(pga, heatdeathoftheuniverse);
	PGASetUp(pga);
	PGARun(pga, evaluate);
	PGADestroy(pga);
	
	MPI_Finalize();
}

