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

/** \file traces.h
 *  The \b traces library, a software library dedicated to processing of power
 *  traces in relation with the Data Encryption Standard (DES).
 *  \author Renaud Pacalet, renaud.pacalet@telecom-paristech.fr
 *  \date 2009-07-29
 *
 * Traces are one dimension arrays of floating point numbers. They are stored in
 * a binary file along with some parameters and their corresponding 64 bits (8
 * bytes) plaintexts and ciphertexts. The format of the trace files is the
 * following:
 * <ol>
 * <li>"HWSec" (a 5 bytes magic number)</li>
 * <li>N, the number of traces in the file (a 4 bytes unsigned integer)</li>
 * <li>L, the number of points per trace (a 4 bytes unsigned integer)</li>
 * <li>K, the 64 bits secret key (a 8 bytes unsigned integer)</li>
 * <li>N * (8 + 8 + L * 4) bytes corresponding to the N traces. The 8 bytes of
 * the plaintext come first, then the 8 bytes of the cycphertext and the L
 * floating point numbers (L * 4 bytes) of the trace.</li>
 * </ol>
 * A trace file containing 50 traces, 100 points each will thus be 20813 bytes
 * long: 5 + 4 + 4 + 50 * (8 + 8 + 100 * 4).
 *
 * Reading a trace file is done by a call to tr_init() which initializes
 * and returns a tr_context: \code
 * #include <traces.h>
 * ...
 * tr_context ctx;
 * ctx = tr_init("MyTraceFile.hws", 1000);
 * \endcode
 * where "MyTraceFile.hws" is a regular trace file in HWSec format and 1000 the
 * maximum number of traces to read from it. Once initialized, the context
 * contains every useful information:
 * <ol>
 * <li>number of traces in context</li>
 * <li>number of points per trace</li>
 * <li>the secret key</li>
 * <li>the plaintexts</li>
 * <li>ciphertexts</li>
 * <li>power traces</li>
 * </ol>
 * 
 * At the end of the trace processing the context can be closed (freed) by a
 * call to tr_free(): \code
 * tr_free(ctx);
 * \endcode
 *
 * The other provided functions can only be used between a call to
 * tr_init() and a call to tr_free().

 * \attention
 * <ol>
 * <li>Most functions of the \b traces library check their input parameters and
 * issue warnings or errors when they carry illegal values. Warnings are
 * printed on the standard error output. Errors are also printed on the
 * standard error output and the program exits with a -1 exit status.</li>
 * <li>The \b traces library uses a single data type to represent all the data of
 * the DES standard: <b>uint64_t</b>. It is a 64 bits unsigned integer.</li>
 * <li>DES data are always right aligned: when the data width is less than 64
 * bits, the meaningful bits are always the rightmost bits of the
 * <b>uint64_t</b>.</li>
 * <li>Power traces are one dimension arrays of floats. Power traces of the
 * trace context are automatically allocated and freed by the tr_init() and
 * tr_free() functions. Any extra power trace must be explicitly declared,
 * allocated and freed:
 * \code
 * float *t;
 * ...
 * t = tr_new_trace (ctx);
 * ...
 * tr_free_trace (ctx, t);
 * \endcode
 * </li>
 * </ol>
 */

#ifndef TRACES_H
#define TRACES_H

/** Magic number identifying trace files in HWSec format. */
#define HWSECMAGICNUMBER "HWSec"

/** The data structure used to manage a set of traces */
struct tr_context_s
{
  int n;			/**< Number of traces in the context */
  int l;			/**< Number of points per trace */
  uint64_t k;			/**< Secret key */
  uint64_t *p;			/**< Plaintexts */
  uint64_t *c;			/**< Ciphertexts */
  float **t;			/**< Power traces */
};

/** Pointer to the data structure */
typedef struct tr_context_s *tr_context;

/******************************************************
 * Trace context initialization, edition and deletion *
 ******************************************************/

/** Reads the trace file <b>filename</b> and initializes the context.
 * Must be called once before using any other function of the trace library on
 * the same context. \return the initialized context. */
tr_context tr_init (char *filename,
		    /**< Name of the trace file in HWSec format */
    /** Maximum number of traces to read from the file (read all traces if 0) */
		    int max);

/** Closes and deallocates the previously initialized context. */
void tr_free (tr_context ctx /**< The context. */ );

/** Trim all the traces of the context, keeping only <b>length</b> 
 * points, starting from point number <b>first_index</b> */
void tr_trim (tr_context ctx,
		    /**< The context. */
	      int first_index,
		    /**< The index of first point to keep. */
	      int length
		    /**< The number of points to keep.*/
  );

/** Selects <b>n</b> traces of the context, starting from trace number <b>first_trace</b>,
 * and discards the others */
void tr_select (tr_context ctx,
		    /**< The context. */
		int first_trace,
		     /**< Index of first trace to keep. */
		int n
	  /**< Number of traces to keep. */
  );

/** Srink all the traces of the context, by replacing each chunk of
 * <b>chunk_size</b> points by their sum. If incomplete, the last chunk is
 * discarded */
void tr_shrink (tr_context ctx,
		    /**< The context. */
		int chunk_size
		   /**< Number of points per chunk. */
  );

/** Writes the context in a HWSec trace file <b>filename</b> */
void tr_dump (tr_context ctx,
		    /**< The context. */
	      char *filename
		   /**< Name of output HWSec trace file. */
  );

/********************************************************************
 * Functions used to get information about a context or to retreive *
 * ciphertexts and power traces from it                             *
 ********************************************************************/

/** Returns the number of traces in a context. \return The number of traces in
 * the context. */
int tr_number (tr_context ctx
		    /**< The context. */
  );

/** Returns the number of points per trace of the context. \return The number of
 * points per trace in the context. */
int tr_length (tr_context ctx
		    /**< The context. */
  );

/** Returns the secret key of the context. \return The secret key of the context.
 * */
uint64_t tr_key (tr_context ctx
		    /**< The context. */
  );

/** Returns the plaintext #<b>i</b> of the context. \return The plaintext #<b>i</b> of
 * the context. */
uint64_t tr_plaintext (tr_context ctx /**< The context. */ ,
		       int i
	  /**< Index of plaintext to return. */
  );

/** Returns the ciphertext #<b>i</b> of the context. \return The ciphertext #<b>i</b> of
 * the context. */
uint64_t tr_ciphertext (tr_context ctx,
		    /**< The context. */
			int i
	  /**< Index of ciphertext to return. */
  );

/** Returns the power trace #<b>i</b> of the context. \return The power trace #<b>i</b> of
 * the context */
float *tr_trace (tr_context ctx,
		    /**< The context. */
		 int i
      /**< Index of trace to return. */
  );

/***********************************************************************
 * Functions used to create, destroy, initialize and copy power traces *
 ***********************************************************************/

/** Allocates a new power trace which size is the size of the traces of the
 * context. \return A pointer to the allocated trace */
float *tr_new_trace (tr_context ctx
		    /**< The context. */
  );

/** Deallocates a power trace previously allocated by tr_new_trace. */
void tr_free_trace (tr_context ctx,
		    /**< The context. */
		    float *t /**< The trace to deallocate. */ );

/** Initializes the trace <b>t</b> with the scalar value <b>val</b> (each point is
 * assigned the value <b>val</b>). The trace must be one of the traces of the
 * currently opened context (as returned by tr_trace) or must have been
 * previously allocated by a call to tr_new_trace. */
void tr_init_trace (tr_context ctx,
		    /**< The context. */
		    float *t, /**< The trace. */
		    float val /**< The initialization value. */ );

/** Copies trace <b>src</b> to <b>dest</b>. <b>dest</b>[i] = <b>src</b>[i]. The traces <b>dest</b> and<b>src</b> 
 * must be existing traces. */
void tr_copy (tr_context ctx,
		    /**< The context. */
	      float *dest, /**< The destination trace. */
	      float *src /**< The source trace. */ );

/**********************************
 * Arithmetic functions on traces *
 **********************************/

/** Adds traces <b>src</b> and <b>dest</b> and stores the result in <b>dest</b>: <b>dest</b>[i] =
 * <b>dest</b>[i] + <b>src</b>[i].  The traces <b>dest</b> and <b>src</b> must be existing traces. */
void tr_acc (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src /**< The source trace. */ );

/** Adds traces <b>src1</b> and <b>src2</b> and stores the result in <b>dest</b>: <b>dest</b>[i] =
 * <b>src1</b>[i] + <b>src2</b>[i]. The traces <b>dest</b>, <b>src1</b> and <b>src2</b> must be existing
 * traces. */
void tr_add (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src1, /**< The first source trace. */
	     float *src2  /**< The second source trace. */
  );

/** Substracts traces <b>src1</b> and <b>src2</b> and stores the result in <b>dest</b>: <b>dest</b>[i]
 * = <b>src1</b>[i] - <b>src2</b>[i] The traces <b>dest</b>, <b>src1</b> and <b>src2</b> must be existing
 * traces. */
void tr_sub (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src1, /**< The first source trace. */
	     float *src2  /**< The second source trace. */
  );

/** Multiplies the trace <b>src</b> by the scalar <b>val</b>: <b>dest</b>[i] = <b>src</b>[i] * <b>val</b> The
 * traces <b>dest</b> and <b>src</b> must be existing traces. */
void tr_scalar_mul (tr_context ctx,
		    /**< The context. */
		    float *dest,/**< The destination trace. */
		    float *src /**< The source trace. */ ,
		    float val/**< The scalar value. */
  );

/** Divides the trace <b>src</b> by the scalar <b>val</b>: <b>dest</b>[i] = <b>src</b>[i] / <b>val</b> The
 * traces <b>dest</b> and <b>src</b> must be existing traces. An error is raised on
 * divisions by zero. */
void tr_scalar_div (tr_context ctx,
		    /**< The context. */
		    float *dest,/**< The destination trace. */
		    float *src /**< The source trace. */ ,
		    float val/**< The scalar value. */
  );

/** Multiplies traces <b>src1</b> and <b>src2</b> and stores the result in <b>dest</b>: <b>dest</b>[i] =
 * <b>src1</b>[i] * <b>src2</b>[i] The traces <b>dest</b>, <b>src1</b> and <b>src2</b> must be existing
 * traces. */
void tr_mul (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src1, /**< The first source trace. */
	     float *src2  /**< The second source trace. */
  );

/** Divides traces <b>src1</b> and <b>src2</b> and stores the result in <b>dest</b>: <b>dest</b>[i] =
 * <b>src1</b>[i] / <b>src2</b>[i] The traces <b>dest</b>, <b>src1</b> and <b>src2</b> must be existing
 * traces. An error is raised on divisions by zero. */
void tr_div (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src1, /**< The first source trace. */
	     float *src2  /**< The second source trace. */
  );

/** Computes the square of trace <b>src</b>: <b>dest</b>[i] = <b>src</b>[i] * <b>src</b>[i] The traces
 * <b>dest</b> and <b>src</b> must be an existing traces. */
void tr_sqr (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src /**< The source trace. */ );

/** Computes the square root of trace <b>src</b>: <b>dest</b>[i] = sqrt(<b>src</b>[i]) The traces
 * <b>dest</b> and <b>src</b> must be an existing traces. An error is raised on negative
 * values. */
void tr_sqrt (tr_context ctx,
		    /**< The context. */
	      float *dest, /**< The destination trace. */
	      float *src /**< The source trace. */ );

/** Computes the absolute value of trace <b>src</b>: <b>dest</b>[i] = (<b>src</b>[i] < 0.0) ?
 * -<b>src</b>[i] : <b>src</b>[i] The traces <b>dest</b> and <b>src</b> must be an existing traces. */
void tr_abs (tr_context ctx,
		    /**< The context. */
	     float *dest, /**< The destination trace. */
	     float *src /**< The source trace. */ );

/** Returns the minimum value of trace <b>t</b> and stores its index in
 * *<b>idx</b>.
\return The minimum value of trace <b>t</b> and the corresponding index in *<b>idx</b>. */
float tr_min (tr_context ctx,
		    /**< The context. */
	      float *t,	/**< The trace. */
	      int *idx /**< The argmin. */ );

/** Returns the maximum value of trace <b>t</b> and stores its index in
 * *<b>idx</b>.
\return The maximum value of trace <b>t</b> and the corresponding index in *<b>idx</b>. */
float tr_max (tr_context ctx,
		    /**< The context. */
	      float *t,	/**< The trace. */
	      int *idx /**< The argmax. */ );

/** Prints trace <b>t</b> in ascii form, one point per line on standard output. */
void tr_print (tr_context ctx,
		    /**< The context. */
	       float *t/**< The trace. */
  );

/** Print trace <b>t</b> in ascii form, one point per line in file <b>fp</b>. */
void tr_fprint (tr_context ctx,
		    /**< The context. */
		FILE * fp, /**< The descriptor of the output file. */
		float *t/**< The trace. */
  );

/** Create two gnuplot files for a set of traces. <b>prefix</b>.dat is the data
 * file containing the <b>n</b> traces <b>t</b>[0]..<b>t</b>[n-1] in gnuplot
 * format. <b>prefix</b>.cmd is a gnuplot command file that can be used to plot
 * them with the command:<br>
 * \code
 * $ gnuplot -persist prefix.cmd
 * \endcode
 * If parameter <b>i</b> is the index of one of the traces (0 <= <b>i</b> <=
 * <b>n</b>-1), the corresponding trace will be plotted in red and with the
 * title "Trace X (0xY)" where X and Y are the decimal and hexadecimal forms of
 * <b>i</b>.  All the other traces are plotted in blue without title. */
void tr_plot (tr_context ctx, /**< The context. */
		/** The prefix of the two file names. The data file name is
                 * prefix.dat and the gnuplot command file name is prefix.cmd.
                 * */
	      char *prefix, int n,
		       /**< The number of traces to plot. */
		/** The index of a trace to plot in red. None if not in the 0..n-1 range. */
	      int i,
	      float **t
			  /**< The traces. */
  );

#endif /* not TRACES_H */
