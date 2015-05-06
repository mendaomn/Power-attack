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
#include <km.h>

#include <tr_pcc.h>

tr_context ctx;                 /* Trace context (see traces.h) */

void read_datafile (char *name, int n);
void dpa_attack (void);

int
main (int argc, char **argv)
{
  int n;                        /* Number of experiments to use. */

  if (!des_check ())
    {
      ERROR (-1, "DES functional test failed");
    }

  if (argc != 3)
    {
      ERROR (-1, "usage: dpa <file> <n>\n  <file>: name of the traces file in HWSec format\n          (e.g. /datas/teaching/courses/HWSec/labs/data/HWSecTraces10000x00800.hws)\n  <n>: number of experiments to use\n");
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
	int i, n, g, trace_len, sbox, hd;
	float *pcc_vector, *t, max = -1;               
	uint64_t ct, final_key=0, best_key=0, key, ks[16];   
	uint64_t r16l16, l16, r16, l15, l16np, l15np, sbo, mask6 = 63, mask4 = 15;
	tr_pcc_context pcc_ctx;	
	
	n = tr_number (ctx);          /* Number of traces in context */
	trace_len = tr_length(ctx);
    tr_trim(ctx, 575, 25);
    trace_len = 25;
/* Attacks one sbox at a time */	
    for (sbox = 7; sbox >= 0; sbox--){
    	best_key=0;
    	max=-1;
		pcc_ctx = tr_pcc_init(trace_len, 64);

		for (i=0; i<n; i++){
			ct = tr_ciphertext(ctx, i);
			r16l16 = des_ip (ct); /* undoes final permutation */	
			l16 = des_right_half (r16l16); /* extracts right half */	
			r16 = des_left_half (r16l16);
			
			t = tr_trace (ctx, i);
			tr_pcc_insert_x(pcc_ctx, t);
			
			for (g = 0, key = UINT64_C(0); g < 64; g++, key += UINT64_C (0x041041041041)){
				sbo = des_sboxes (des_e (l16) ^ key); 
				l15 = r16 ^ des_p(sbo);
				l15np = des_n_p(l15) & mask4;
				l16np = des_n_p(l16) & mask4;
				hd = hamming_distance (l15np, l16np);	

				tr_pcc_insert_y(pcc_ctx, g, hd);
			}
		}
		tr_pcc_consolidate(pcc_ctx);

		/* Finds the best key among the pcc computed */
		for (g = 0, key = UINT64_C(0); g < 64; g++, key += UINT64_C (0x041041041041)){
			pcc_vector = tr_pcc_get_pcc(pcc_ctx, g);

			for(i=0; i<trace_len; i++){
				if (pcc_vector[i] > max){
					max = pcc_vector[i];
					best_key = key & mask6;
				}
			}
		}

		tr_pcc_free(pcc_ctx);
		
		final_key |= best_key;
		mask6 <<= 6;
    	mask4 <<= 4;
    }

	/* Checks 48 bit correctness against the prestored correct key */
	key = tr_key (ctx); 
	des_ks (ks, key);   
	if (final_key == ks[15]) 
			printf ("%012" PRIx64 "\n", final_key);	

}
