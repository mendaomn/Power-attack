/**********************************************************************************
Copyright Institut Telecom
Contributors: Renaud Pacalet (renaud.pacalet@telecom-paristech.fr)

This software is a computer program whose purpose is to experiment timing and
power attacks against crypto-processors.

This software is governed by the CeCILL license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms. For more
information see the LICENCE-fr.txt or LICENSE-en.txt files.
**********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <utils.h>
#include <traces.h>
#include <des.h>

#include <tr_pcc.h>

/* The P permutation table, as in the standard. The first entry (16) is the
 * position of the first (leftmost) bit of the result in the input 32 bits word.
 * Used to convert target bit index into SBox index (just for printed summary
 * after attack completion). */
int p_table[32] = {
  16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25
};

tr_context ctx;                 /* Trace context (see traces.h) */
int target_bit;                 /* Index of target bit. */
int target_sbox;                /* Index of target SBox. */
int best_guess;                 /* Best guess */
int best_idx;                   /* Best argmax */
float best_max;                 /* Best max sample value */
float *dpa[64];                 /* 64 DPA traces */

/* A function to allocate cipher texts and power traces, read the
 * datafile and store its content in allocated context. */
void read_datafile (char *name, int n);

/* Compute the average power trace of the traces context ctx, print it in file
 * <prefix>.dat and print the corresponding gnuplot command in <prefix>.cmd. In
 * order to plot the average power trace, type: $ gnuplot -persist <prefix>.cmd
 * */
void average (char *prefix);

/* Decision function: takes a ciphertext and returns an array of 64 values for
 * an intermediate DES data, one per guess on a 6-bits subkey. In this example
 * the decision is the computed value of bit index <target_bit> of L15. Each of
 * the 64 decisions is thus 0 or 1.*/
void decision (uint64_t ct, int d[64]);

/* Apply P. Kocher's DPA algorithm based on decision function. Computes 64 DPA
 * traces dpa[0..63], best_guess (6-bits subkey corresponding to highest DPA
 * peak), best_idx (index of sample with maximum value in best DPA trace) and
 * best_max (value of sample with maximum value in best DPA trace). */
void dpa_attack (void);

int
main (int argc, char **argv)
{
  int n;                        /* Number of experiments to use. */
  int g;                        /* Guess on a 6-bits subkey */

  if (!des_check ())
    {
      ERROR (-1, "DES functional test failed");
    }

  if (argc != 4)
    {
      ERROR (-1, "usage: dpa <file> <n> <b>\n  <file>: name of the traces file in HWSec format\n          (e.g. /datas/teaching/courses/HWSec/labs/data/HWSecTraces10000x00800.hws)\n  <n>: number of experiments to use\n  <b>: index of target bit in L15 (1 to 32, as in DES standard)\n");
    }

  n = atoi (argv[2]); /* Number of experiments to use */
  if (n < 1)                    /* If invalid number of experiments. */
    {
      ERROR (-1, "invalid number of experiments: %d (shall be greater than 1)", n);
    }
 
  /* Read power traces and ciphertexts. Name of data file is argument #1. n is
   * the number of experiments to use. */
  read_datafile (argv[1], n);
   
  dpa_attack ();

  for (g = 0; g < 64; g++)      /* For all guesses for 6-bits subkey */
    {
      tr_free_trace (ctx, dpa[g]);
    }
  tr_free (ctx);                /* Free traces context */
  return 0;                     /* Exits with "everything went fine" status. */
}

void
read_datafile (char *name, int n)
{
  int tn;

  ctx = tr_init (name, n);
  tn = tr_number (ctx);
  if (tn != n)
    {
      tr_free (ctx);
      ERROR (-1, "Could not read %d experiments from traces file. Traces file contains %d experiments.", n, tn);
    }
}

void
dpa_attack (void)
{
	int i;                        /* Loop index */
	int n;                        /* Number of traces. */
	int g;                        /* Guess on a 6-bits subkey */
	int trace_len;                      /* Argmax (index of sample with maximum value in a trace) */
	
	float *pcc_vector;              
	float *t;                     /* Power trace */
	float max;                    

	uint64_t ct;                  /* Ciphertext */
	uint64_t best_key;   
	tr_pcc_context pcc_ctx;

	n = tr_number (ctx);          /* Number of traces in context */
	trace_len = tr_length(ctx);
    for (sbox = 0; sbox >= 0; sbox--){
		pcc_ctx = tr_pcc_init(trace_len, 64);
		for (i=0; i<n; i++){
			r16l16 = des_ip (ct[i]); /* undoes final permutation */
			l16 = des_right_half (r16l16); /* extracts right half */
			t = tr_trace (ctx, i);
			tr_pcc_insert_x(pcc_ctx, t);
			for (g = 0; g < 64; g++){
				key = ((unsigned long long) g) << (42 - 6*sbox); 
				sbo = des_sboxes (des_e (l16) ^ key);  
				hw = hamming_weight (sbo); 
				tr_pcc_insert_y(pcc_ctx, g, hw);
			}
		}
		pcc_consolidate(ctx);
		for (g=0; g<64; g++){
			pcc_vector = pcc_get_pcc(ctx, g);
			for(i=0; i<trace_len; i++){
				if (pcc_vector[i] > max){
					max = pcc_vector[i];
					best_key = key;
				}
			}
		}
		pcc_free(ctx);
		
    } //sbox
}
