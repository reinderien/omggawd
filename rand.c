/*
Genetic Algorithm WTF Decisionator
(c) Greg Toombs 2013 (should I really put my name on this?)
*/

#include <assert.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void b64_out(int (*dorand)(), int index) {
	/*int rbits = 0;
	for (int rmax = RAND_MAX; rmax; rmax >>= 1)
		rbits++;
	int rbytes = rbits/8;

	printf("RAND_MAX=0x%X (%d bits, %d bytes)\n", RAND_MAX, rbits, rbytes);*/
	
	// This is actually something like 3.875, but who cares
	int rbytes = 3;
	
	// Call Gnu "base64" to put the data in stomp-able format
	// wrap at 100 cols
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "base64 -w100 > stomped_%d.txt", index);
	FILE *pin = popen(cmd, "w");
	if (!pin) {
		perror("Couldn't run base64");
		return;
	}
	int fd = fileno(pin);
	
	// 6 bits of rand -> 8 bits of base64
	// 100 cols = x8/6; x = 75 bytes
	// 20000 rows (so sayeth the stomper)
	for (int x = 0; x < 75*20000; x += rbytes) {
		int r = dorand();
		assert(rbytes == write(fd, &r, rbytes));
	}
	
	pclose(pin);
}

double stomp(int index) {
	// Regex to parse Stompy's entropy summary lines x2
	regex_t rex;
	assert(!regcomp(&rex, "level *: (.+) anomalous bits, (.+) OK",
		REG_EXTENDED));
	
	// Start Stompy and feed him some goodies
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		"stompy/stompy -o /dev/null -R stomped_%d.txt", index);
	FILE *pout = popen(cmd, "r");
	if (!pout) {
		perror("No stomping :(");
		return -1;
	}
		
	int anom_alpha = -1, ok_alpha = -1, anom_bit = -1, ok_bit = -1;
	
	char line[1024];
	// Read and re-display Stompy output while we look for the summary
	while (fgets(line, sizeof(line), pout)) {
		// printf("s:    %s", line);
	
		regmatch_t matches[3];
		int result = regexec(&rex, line, 3, matches, 0);
		
		if (result == REG_NOERROR) {
			line[matches[0].rm_eo] = '\0';
			line[matches[1].rm_eo] = '\0';
			int d1 = atoi(line + matches[1].rm_so),
			    d2 = atoi(line + matches[2].rm_so);
			if (anom_alpha == -1 && ok_alpha == -1) {
				anom_alpha = d1;
				ok_alpha = d2;
			}
			else {
				anom_bit = d1;
				ok_bit = d2;
				break;
			}
		}
		else assert(result == REG_NOMATCH);
	}
	
	pclose(pout);
	
	if (anom_alpha == -1 || anom_bit == -1 || ok_alpha == -1 || ok_bit == -1)
		return -1;
	
	// Form a composite entropy score based on Stompy's reported anomalous and
	// OK bits on both the alphabet and bit levels
	
	double composite = (ok_alpha + ok_bit) /
		(double)(ok_alpha + ok_bit + anom_alpha + anom_bit);
	return composite;
}

