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

/** \file utils.h
 *  Some utility functions and macros.
 *
 *  When available the macros are much simpler to use, so if they fit your
 *  needs, do not even look at the functions.
 *
 *  \author Renaud Pacalet, renaud.pacalet@telecom-paristech.fr
 *  \date 2009-07-08
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/** Print an error message and exit with -1 status. \e s is the desired exit
 * status, followed by a printf-like formating string and an optional
 * printf-like variable number of arguments. Example: if file foo.c contains:
 * \code
 * void bar(void)
 *   {
 *     ...
 *     A = 15;
 *     ERROR (-1, "invalid value of parameter A: %d", A);
 *     ...
 *   }
 * \endcode
 * and the ERROR macro (at line 47 of foo.c) is executed, it will print the
 * message:<br>
\verbatim
*** error in file foo.c, line 47, function bar:
*** invalid value of parameter A: 15
\endverbatim
 * on the standard error and then exit with status -1. */
#define ERROR(s,...) error(__FILE__, __LINE__, __func__, (s), __VA_ARGS__)

/** Print a warning message. Takes a printf-like formating string followed by
 * an optional printf-like variable number of arguments. Example: if file foo.c
 * contains: \code
 * void bar(void)
 *   {
 *     ...
 *     A = 15;
 *     WARNING ("invalid value of parameter A: %d", A);
 *     ...
 *   }
 * \endcode
 * and the WARNING macro (at line 47 of foo.c) is executed, it will print the
 * message:<br>
\verbatim
*** warning in file foo.c, line 47, function bar:
*** invalid value of parameter A: 15
\endverbatim
 * on the standard error. */
#define WARNING(...) warning(__FILE__, __LINE__, __func__, __VA_ARGS__)

/** Wrapper around the regular malloc memory allocator. Allocates \e n bytes and
 * returns a pointer to the allocated memory. Errors are catched, no need to
 * check result. \return pointer to allocated memory area. */
#define XMALLOC(n) xmalloc(__FILE__, __LINE__, __func__, (n))

/** Wrapper around the regular calloc memory allocator. Allocates memory for an
 * array of \e n elements of \e s bytes each and returns a pointer to the
 * allocated memory. Errors are catched, no need to check result. \return
 * pointer to allocated memory area. */
#define XCALLOC(n,s) xcalloc(__FILE__, __LINE__, __func__, (n), (s))

/** Wrapper around the regular realloc memory allocator. Resize the memory area
 * pointed to py \e p to \e s bytes and returns a pointer to the allocated memory.
 * Errors are catched, no need to check result. \return pointer to allocated
 * memory area. */
#define XREALLOC(p,s) xrealloc(__FILE__, __LINE__, __func__, (p), (s))

/** Wrapper around the regular fopen. Opens file \e f in mode \e m. Errors are
 * catched, no need to check result. \return The FILE pointer to the opened
 * file. */
#define XFOPEN(f,m) xfopen(__FILE__, __LINE__, __func__, (f), (m))

/** Returns the Hamming weight of a 64 bits word.
 * Note: the input's width can be anything between 0 and 64, as long as the
 * unused bits are all zeroes. \return The Hamming weight of the input as a 64
 * bits ::uint64_t. */
int hamming_weight (uint64_t val /**< The 64 bits input. */ );

/** Returns the Hamming distance between two 64 bits words.
 * Note: the width of the inputs can be anything between 0 and 64, as long as
 * they are the same, aligned and that the unused bits are all zeroes. \return
 * The Hamming distance between the two inputs as a 64 bits ::uint64_t. */
int hamming_distance (uint64_t val1 /**< The first 64 bits input. */ ,
		      uint64_t val2
		  /**< The second 64 bits input. */
  );

/** Prints an error message and exit with -1 status.
 * Takes a variable number of arguments, as printf. */
void error (const char *file /**< File name. */ ,
	    const int line /**< Line number. */ ,
	    const char *fnct /**< Name of calling function. */ ,
	    const int status /**< Exit status. */ ,
	    const char *frm, /**< A printf-like formatting string */
	    ...	 /**< A variable number of arguments. */
  );

/** Prints a warning message.
 * Takes a variable number of arguments, as printf. */
void warning (const char *file /**< File name. */ ,
	      const int line /**< Line number. */ ,
	      const char *fnct /**< Name of calling function. */ ,
	      const char *frm,
			     /**< A printf-like formatting string */
	      .../**< A variable number of arguments. */
  );

/** Wrapper around the regular malloc memory allocator. Errors are catched, no
 * need to check result. \return pointer to allocated memory area. */
void *xmalloc (const char *file /**< File name. */ ,
	       const int line /**< Line number. */ ,
	       const char *fnct /**< Name of calling function. */ ,
	       const size_t size
		/**< Size of an element. */
  );

/** Wrapper around the regular calloc memory allocator. Errors are catched, no
 * need to check result. \return pointer to allocated memory area. */
void *xcalloc (const char *file /**< File name. */ ,
	       const int line /**< Line number. */ ,
	       const char *fnct /**< Name of calling function. */ ,
	       const size_t nmemb /**< Number of elements to allocate. */ ,
	       const size_t size /**< Size of an element. */
  );

/** Wrapper around the regular realloc memory allocator. Errors are catched, no
 * need to check result. \return pointer to allocated memory area. */
void *xrealloc (const char *file /**< File name. */ ,
		const int line /**< Line number. */ ,
		const char *fnct /**< Name of calling function. */ ,
		void *ptr /**< Source pointer. */ ,
		const size_t size /**< Size of new memory area. */
  );

/** Wrapper around the regular fopen. Errors are catched, no
 * need to check result. \return The FILE pointer to the opened file. */
FILE *xfopen (const char *file /**< File name. */ ,
	      const int line /**< Line number. */ ,
	      const char *fnct /**< Name of calling function. */ ,
	      const char *name /**< File name */ ,
	      const char *mode
		     /**< Mode */
  );

#endif /** not UTILS_H */
