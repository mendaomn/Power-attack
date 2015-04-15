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
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>

#include <utils.h>
#include <traces.h>

tr_context
tr_init (char *filename, int max)
{
  char *dummy;
  int MagicNumberLength, i;
  FILE *fp;
  tr_context ctx;

  if (max < 0)
    {
      ERROR (-1, "invalid maximum number of traces: %d", max);
    }
  ctx = XCALLOC (1, sizeof (struct tr_context_s));
  fp = fopen (filename, "rb");
  if (fp == NULL)
    {
      ERROR (-1, "cannot open file %s", filename);
    }
  MagicNumberLength = strlen (HWSECMAGICNUMBER);
  dummy = XCALLOC (MagicNumberLength, sizeof (char));
  if ((fread (dummy, sizeof (char), MagicNumberLength, fp) !=
       MagicNumberLength) ||
      (strncmp (dummy, HWSECMAGICNUMBER, MagicNumberLength) != 0))
    {
      ERROR (-1, "wrong magic number; is this a real HWSec trace file?");
    }
  free (dummy);
  if (fread (&(ctx->n), sizeof (uint32_t), 1, fp) != 1)
    {
      ERROR (-1,
	     "cannot read number of traces; is this a real HWSec trace file?");
    }
  if (max == 0)
    {
      max = ctx->n;
    }
  else if (ctx->n >= max)
    {
      ctx->n = max;
    }
  else
    {
      ERROR (-1, "not enough traces in trace file (%d < %d)", ctx->n, max);
    }
  if (fread (&(ctx->l), sizeof (uint32_t), 1, fp) != 1)
    {
      ERROR (-1,
	     "cannot read traces length; is this a real HWSec trace file?");
    }
  if (fread (&(ctx->k), sizeof (uint64_t), 1, fp) != 1)
    {
      ERROR (-1, "cannot read secret key; is this a real HWSec trace file?");
    }
  ctx->p = XCALLOC (ctx->n, sizeof (uint64_t));
  ctx->c = XCALLOC (ctx->n, sizeof (uint64_t));
  ctx->t = XCALLOC (ctx->n, sizeof (float *));
  for (i = 0; i < ctx->n; i++)
    {
      ctx->t[i] = NULL;
    }
  for (i = 0; i < ctx->n; i++)
    {
      ctx->t[i] = XCALLOC (ctx->l, sizeof (float));
      if (fread (&(ctx->p[i]), sizeof (uint64_t), 1, fp) != 1)
	{
	  ERROR (-1,
		 "cannot read plaintext #%d; is this a real HWSec trace file?",
		 i);
	}
      if (fread (&(ctx->c[i]), sizeof (uint64_t), 1, fp) != 1)
	{
	  ERROR (-1,
		 "cannot read ciphertext #%d; is this a real HWSec trace file?",
		 i);
	}
      if (fread (ctx->t[i], sizeof (float), ctx->l, fp) != ctx->l)
	{
	  ERROR (-1,
		 "cannot read trace #%d; is this a real HWSec trace file?",
		 i);
	}
    }
  fclose (fp);
  return ctx;
}

void
tr_free (tr_context ctx)
{
  int i;

  free (ctx->p);
  free (ctx->c);
  for (i = 0; i < ctx->n; i++)
    {
      free (ctx->t[i]);
    }
  free (ctx->t);
  free (ctx);
}

void
tr_trim (tr_context ctx, int first_index, int length)
{
  int i;
  float *t;

  if (first_index < 0 || first_index >= ctx->l || length < 0 ||
      first_index + length > ctx->l)
    {
      ERROR (-1,
	     "invalid parameters value: first_index=%d, length=%d (traces length=%d)",
	     first_index, length, ctx->l);
    }
  for (i = 0; i < ctx->n; i++)
    {
      t = XCALLOC (length, sizeof (float));
      memcpy (t, &(ctx->t[i][first_index]), length * sizeof (float));
      free (ctx->t[i]);
      ctx->t[i] = t;
    }
  ctx->l = length;
}

void
tr_select (tr_context ctx, int first_trace, int n)
{
  int i;
  float **t;
  uint64_t *c;

  if (first_trace < 0 || first_trace >= ctx->n || n < 0 ||
      first_trace + n > ctx->n)
    {
      ERROR (-1,
	     "invalid parameters value: first_trace=%d, n=%d (number of traces=%d)",
	     first_trace, n, ctx->n);
    }
  t = XCALLOC (n, sizeof (float *));
  c = XCALLOC (n, sizeof (uint64_t));
  for (i = 0; i < first_trace; i++)
    {
      free (ctx->t[i]);
    }
  for (i = 0; i < n; i++)
    {
      t[i] = ctx->t[i + first_trace];
      c[i] = ctx->c[i + first_trace];
    }
  for (i = first_trace + n; i < ctx->n; i++)
    {
      free (ctx->t[i]);
    }
  free (ctx->c);
  ctx->c = c;
  free (ctx->t);
  ctx->t = t;
  ctx->n = n;
}

void
tr_shrink (tr_context ctx, int chunk_size)
{
  int i, j, k, l;
  float *t, *p;

  if (chunk_size < 1 || chunk_size > ctx->l)
    {
      ERROR (-1,
	     "invalid parameters value: chunk_size=%d (traces length=%d)",
	     chunk_size, ctx->l);
    }
  l = ctx->l / chunk_size;
  for (i = 0; i < ctx->n; i++)
    {
      t = XCALLOC (l, sizeof (float));
      p = ctx->t[i];
      for (j = 0; j < l; j++)
	{
	  t[j] = 0.0;
	  for (k = 0; k < chunk_size; k++)
	    {
	      t[j] += *p;
	      p += 1;
	    }
	}
      free (ctx->t[i]);
      ctx->t[i] = t;
    }
  ctx->l = l;
}

void
tr_dump (tr_context ctx, char *filename)
{
  int MagicNumberLength, i;
  FILE *fp;

  fp = fopen (filename, "wb");
  if (fp == NULL)
    {
      ERROR (-1, "cannot open file %s for writing", filename);
    }
  MagicNumberLength = strlen (HWSECMAGICNUMBER);
  if (fwrite (HWSECMAGICNUMBER, sizeof (char), MagicNumberLength, fp) !=
      MagicNumberLength)
    {
      ERROR (-1, "write error");
    }
  if (fwrite (&(ctx->n), sizeof (uint32_t), 1, fp) != 1)
    {
      ERROR (-1, "write error");
    }
  if (fwrite (&(ctx->l), sizeof (uint32_t), 1, fp) != 1)
    {
      ERROR (-1, "write error");
    }
  if (fwrite (&(ctx->k), sizeof (uint64_t), 1, fp) != 1)
    {
      ERROR (-1, "write error");
    }
  for (i = 0; i < ctx->n; i++)
    {
      if (fwrite (&(ctx->p[i]), sizeof (uint64_t), 1, fp) != 1)
	{
	  ERROR (-1, "write error");
	}
      if (fwrite (&(ctx->c[i]), sizeof (uint64_t), 1, fp) != 1)
	{
	  ERROR (-1, "write error");
	}
      if (fwrite (ctx->t[i], sizeof (float), ctx->l, fp) != ctx->l)
	{
	  ERROR (-1, "write error");
	}
    }
  fclose (fp);
}

int
tr_number (tr_context ctx)
{
  return ctx->n;
}

int
tr_length (tr_context ctx)
{
  return ctx->l;
}

uint64_t
tr_key (tr_context ctx)
{
  return ctx->k;
}

uint64_t
tr_plaintext (tr_context ctx, int i)
{
  if (i < 0 || i > ctx->n)
    {
      ERROR (-1,
	     "no plaintext #%d in context (number of plaintexts=%d)", i,
	     ctx->n);
    }
  return ctx->p[i];
}

uint64_t
tr_ciphertext (tr_context ctx, int i)
{
  if (i < 0 || i > ctx->n)
    {
      ERROR (-1,
	     "no ciphertext #%d in context (number of ciphertexts=%d)", i,
	     ctx->n);
    }
  return ctx->c[i];
}

float *
tr_trace (tr_context ctx, int i)
{
  if (i < 0 || i > ctx->n)
    ERROR (-1, "no trace #%d in context (number of traces=%d)", i, ctx->n);
  return ctx->t[i];
}

float *tr_new_trace_1 (int l);
void tr_free_trace_1 (int l, float *t);
void tr_init_trace_1 (int l, float *t, float val);
void tr_copy_1 (int l, float *dest, float *src);
void tr_acc_1 (int l, float *dest, float *src);
void tr_add_1 (int l, float *dest, float *src1, float *src2);
void tr_sub_1 (int l, float *dest, float *src1, float *src2);
void tr_scalar_mul_1 (int l, float *dest, float *src, float val);
void tr_scalar_div_1 (int l, float *dest, float *src, float val);
void tr_mul_1 (int l, float *dest, float *src1, float *src2);
void tr_div_1 (int l, float *dest, float *src1, float *src2);
void tr_sqr_1 (int l, float *dest, float *src);
void tr_sqrt_1 (int l, float *dest, float *src);
void tr_abs_1 (int l, float *dest, float *src);
float tr_min_1 (int l, float *t, int *idx);
float tr_max_1 (int l, float *t, int *idx);
void tr_print_1 (int l, float *t);
void tr_fprint_1 (int l, FILE * fp, float *t);

float *
tr_new_trace (tr_context ctx)
{
  return tr_new_trace_1 (ctx->l);
}

void
tr_free_trace (tr_context ctx, float *t)
{
  tr_free_trace_1 (ctx->l, t);
}

void
tr_init_trace (tr_context ctx, float *t, float val)
{
  tr_init_trace_1 (ctx->l, t, val);
}

void
tr_copy (tr_context ctx, float *dest, float *src)
{
  tr_copy_1 (ctx->l, dest, src);
}

void
tr_acc (tr_context ctx, float *dest, float *src)
{
  tr_acc_1 (ctx->l, dest, src);
}

void
tr_add (tr_context ctx, float *dest, float *src1, float *src2)
{
  tr_add_1 (ctx->l, dest, src1, src2);
}

void
tr_sub (tr_context ctx, float *dest, float *src1, float *src2)
{
  tr_sub_1 (ctx->l, dest, src1, src2);
}

void
tr_scalar_mul (tr_context ctx, float *dest, float *src, float val)
{
  tr_scalar_mul_1 (ctx->l, dest, src, val);
}

void
tr_scalar_div (tr_context ctx, float *dest, float *src, float val)
{
  tr_scalar_div_1 (ctx->l, dest, src, val);
}

void
tr_mul (tr_context ctx, float *dest, float *src1, float *src2)
{
  tr_mul_1 (ctx->l, dest, src1, src2);
}

void
tr_div (tr_context ctx, float *dest, float *src1, float *src2)
{
  tr_div_1 (ctx->l, dest, src1, src2);
}

void
tr_sqr (tr_context ctx, float *dest, float *src)
{
  tr_sqr_1 (ctx->l, dest, src);
}

void
tr_sqrt (tr_context ctx, float *dest, float *src)
{
  tr_sqrt_1 (ctx->l, dest, src);
}

void
tr_abs (tr_context ctx, float *dest, float *src)
{
  tr_abs_1 (ctx->l, dest, src);
}

float
tr_min (tr_context ctx, float *t, int *idx)
{
  return tr_min_1 (ctx->l, t, idx);
}

float
tr_max (tr_context ctx, float *t, int *idx)
{
  return tr_max_1 (ctx->l, t, idx);
}

void
tr_print (tr_context ctx, float *t)
{
  tr_print_1 (ctx->l, t);
}

void
tr_fprint (tr_context ctx, FILE * fp, float *t)
{
  tr_fprint_1 (ctx->l, fp, t);
}

float *
tr_new_trace_1 (int l)
{
  return XCALLOC (l, sizeof (float));
}

void
tr_free_trace_1 (int l, float *t)
{
  free (t);
}

void
tr_init_trace_1 (int l, float *t, float val)
{
  int i;

  for (i = 0; i < l; i++)
    {
      t[i] = val;
    }
}

void
tr_copy_1 (int l, float *dest, float *src)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src[i];
    }
}

void
tr_acc_1 (int l, float *dest, float *src)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] += src[i];
    }
}

void
tr_add_1 (int l, float *dest, float *src1, float *src2)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src1[i] + src2[i];
    }
}

void
tr_sub_1 (int l, float *dest, float *src1, float *src2)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src1[i] - src2[i];
    }
}

void
tr_scalar_mul_1 (int l, float *dest, float *src, float val)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src[i] * val;
    }
}

void
tr_scalar_div_1 (int l, float *dest, float *src, float val)
{
  int i;

  if (val == 0.0)
    {
      ERROR (-1, "division by zero");
    }
  for (i = 0; i < l; i++)
    {
      dest[i] = src[i] / val;
    }
}

void
tr_mul_1 (int l, float *dest, float *src1, float *src2)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src1[i] * src2[i];
    }
}

void
tr_div_1 (int l, float *dest, float *src1, float *src2)
{
  int i;

  for (i = 0; i < l; i++)
    {
      if (src2[i] == 0.0)
	{
	  ERROR (-1, "division by zero");
	}
      dest[i] = src1[i] / src2[i];
    }
}

void
tr_sqr_1 (int l, float *dest, float *src)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = src[i] * src[i];
    }
}

void
tr_sqrt_1 (int l, float *dest, float *src)
{
  int i;

  for (i = 0; i < l; i++)
    {
      if (src[i] < 0.0)
	{
	  ERROR (-1, "negative value");
	}
      dest[i] = sqrt (src[i]);
    }
}

void
tr_abs_1 (int l, float *dest, float *src)
{
  int i;

  for (i = 0; i < l; i++)
    {
      dest[i] = fabs (src[i]);
    }
}

float
tr_min_1 (int l, float *t, int *idx)
{
  int i;
  float min;

  min = t[0];
  *idx = 0;
  for (i = 1; i < l; i++)
    {
      if (t[i] < min)
	{
	  min = t[i];
	  *idx = i;
	}
    }
  return min;
}

float
tr_max_1 (int l, float *t, int *idx)
{
  int i;
  float max;

  max = t[0];
  *idx = 0;
  for (i = 1; i < l; i++)
    {
      if (t[i] > max)
	{
	  max = t[i];
	  *idx = i;
	}
    }
  return max;
}

void
tr_print_1 (int l, float *t)
{
  int i;

  for (i = 0; i < l; i++)
    {
      printf ("%e\n", t[i]);
    }
}

void
tr_fprint_1 (int l, FILE * fp, float *t)
{
  int i;

  for (i = 0; i < l; i++)
    {
      fprintf (fp, "%e\n", t[i]);
    }
}

void
tr_plot (tr_context ctx, char *prefix, int n, int i, float **t)
{
  FILE *fpd, *fpc;
  char *fname, *title;
  int j;

  title = NULL;
  if (n < 1)
    {
      ERROR (-1, "Invalid number of traces to plot (%d)\n", n);
    }
  if (i >= 0 && i < n)
    {
      title = XCALLOC (100, sizeof (char));
      sprintf (title, "Trace #%d (0x%x)", i, i);
    }
  else
    {
      i = -1;
    }
  fname = XCALLOC (strlen (prefix) + 5, sizeof (char));
  sprintf (fname, "%s.cmd", prefix);
  fpc = XFOPEN (fname, "w");
  sprintf (fname, "%s.dat", prefix);
  fpd = XFOPEN (fname, "w");
  fprintf (fpc, "plot \\\n");
  for (j = 0; j < n; j++)
    {
      tr_fprint (ctx, fpd, t[j]);
      fprintf (fpd, "\n\n");
      if (j != i)
	{
	  fprintf (fpc, "'%s' index %d notitle with lines linecolor 3", fname, j);
          if (i != -1 || j != n - 1)
            {
	      fprintf (fpc, ",\\\n");
            }
	}
    }
  if (i != -1)
    {
      fprintf (fpc, "'%s' index %d title '%s' with lines linecolor 1", fname, i, title);
    }
  fprintf (fpc, "\n");
  fclose (fpd);
  fclose (fpc);
  free (fname);
}
