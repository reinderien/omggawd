#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libbrahe/prng.h"

// Random test variables
int bfreq[2];
#define BFREQ_N (sizeof(bfreq)/sizeof(*bfreq))
int dfreq[16];
#define DFREQ_N (sizeof(dfreq)/sizeof(*dfreq))
int distance;

// Number of times to call each random function
#define NTEST 1000000

// Initialize the random test variables
void initTest() {
	int i = BFREQ_N;
	do bfreq[--i] = 0; while(i);
	i = DFREQ_N;
	do dfreq[--i] = 0; while(i);
	distance = 0;
}

// Test a single random value
void addTest(bool x) {
	// Uniform distribution
	bfreq[!x]++;
	
	// Distance between 0s
	if (x) distance++;
	else {
		if (distance > DFREQ_N-1)
			distance = DFREQ_N-1;
		dfreq[distance]++;
		distance = 0;
	}
}

double getScore() {
	// Start with the uniform distribution of values
	double error = fabs((bfreq[0] - bfreq[1]) / (double)NTEST);
	
	// Check for uniform 0-distance distribution
	double expected = 0.25;
	for (int n = 0; n < DFREQ_N; n++) {
		double actual = dfreq[n] / (double)NTEST;
		error += fabs(actual - expected);
		if (n < DFREQ_N)
			expected /= 2;
	}
	return error;
}

// Test crappy C rand
void test_crap() {
	srand(time(NULL));
	initTest();
	for (int t = NTEST; t; t--)
		addTest(rand() & 1);
	printf("%25s score: %f\n", "rand", getScore());
}

#define TEST_BRAHE(prng) test_brahe(BRAHE_PRNG_##prng, #prng)

// Test some good prngs from libbrahe
void test_brahe(brahe_prng_type_t type, const char *name) {
	brahe_prng_state_t brahe;
	if (!brahe_prng_init(&brahe, type, time(NULL)))
		return;
	
	initTest();
	for (int t = NTEST; t; t--)
		addTest(brahe_prng_next(&brahe) & 1);
	
	brahe_prng_free(&brahe);	
	printf("%25s score: %f\n", name, getScore());
}

void test_fool()
{
	initTest();

    unsigned run_count;
    unsigned one_count;

	for (int t = NTEST; t; t--)
	{
		bool next;
	   if (one_count == 0) {
		    unsigned i = run_count;
		    while (i & 1 == 1) {
		        one_count++;
		        i >>= 1;
		    }
		    run_count++;
		    next = false;
		}
		else
		{
			one_count--;
			next = true;
		}
		addTest(next);
	}
	printf("%25s score: %f\n", "fool", getScore());
}

void testall() {
	test_crap();
	TEST_BRAHE(MARSENNE_TWISTER);
	TEST_BRAHE(KISS);
	TEST_BRAHE(CMWC4096);
	TEST_BRAHE(MWC1038);
	TEST_BRAHE(ISAAC);
	test_fool();
}
