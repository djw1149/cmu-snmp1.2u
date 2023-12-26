/*****************************************************************************
*                                                                            *
*                                   NOTICE                                   *
*                                                                            *
*           Proprietary Materials of Bolt Beranek and Newman Inc.            *
*           and its subsidiaries.  Used under license.  Protected            *
*           as trade secrets  and by federal statutory copyright.            *
*                                                                            *
*   File:   cdefs.h                                                          *
*                                                                            *
*   Contents:   C style definitions useful to all programs.                  *
*                                                                            *
*   Description:    defines for C logical operators, language extensions,    *
*                   macros of general use, byte and word mask and sizes,     *
*                   standard defined types                                   *
*                                                                            *
*   History:                                                                 *
*   30-Mar-89 CLBrooks rewritten for BSD derived UNIX systems
*                                                                            *
*****************************************************************************/

#ifndef cdefs_ALREADY_INCLUDED
#define cdefs_ALREADY_INCLUDED 1

/*** INCLUDES ***/

#ifndef isalpha
#include <ctype.h>
#endif

/*** CONSTANTS AND MACROS ***/

/* system dependent masks and constants */

#ifdef sun 
#define SUN_NBBY 8
#endif

/*------------------*/


#ifndef BYTSIZE
#    define BYTSIZE	8
#endif

#ifndef BYTESIZE
#    define BYTESIZE	8
#endif

#define WORDSIZE 	sizeof(int)
#define LOBYT   	0xFF
#define HIBYT 		(LOBYT<<BYTSIZE)

#define	READMODE	0
#define	WRITEMODE	1
#define	RDWTMODE	2
#define	RDWTEXCL	4
#define MAXFNAME       15       /* max length of unix filename, plus null 
                                  term */

/* C style constants */

#define TRUE 	1
#define FALSE 	0
#define IS 	==
#define ISNOT 	!=
#define AND 	&&
#define OR 	||
#define NOT 	!
#define YES     1
#define NO      0
#define SUCCESS  0      /* system and procedure call returns */
#define FAILURE (-1)    /* ... */
#define ERR_EXIT FAILURE      /* defined for the PC interface.     */
#define EOS     '\0'    /* End Of String */

/* obsolete style constants */

#define ERRRET 	FAILURE /* system call returns */
#define OK     	SUCCESS /* ditto */
#define ISNT 	ISNOT


/* c language expansions */

#define UNTIL(x)  	while(!(x))
#define FOREVER		for (;;)

/* obsolete c language expansions */

#define elif    else if
#define repeat  do
#define until(x)        while (!(x))

typedef unsigned short boolean;

#define btou(x) ((unsigned) (BYTEMASK & (x)))    /* an anachronism for byte to 
  				                  * unsigned conversions */
#ifndef NULL
#define NULL 0
#endif

/* useful macros */

#ifndef MAX
#define  MAX(A, B) ((A) > (B) ? (A) : (B))
#define  MIN(A, B) ((A) < (B) ? (A) : (B))
#endif  /* MAX */

#define ischar(Q) isalpha(Q)
#define isnum(A)  isdigit(A)
#define ishex(Q)  isxdigit(Q)
#define iswhite(A) ((A) == ' ' || (A) == '\t')
#define isprntbl(A) isprint(A)

#ifndef max
#define  max(A, B) ((A) > (B) ? (A) : (B))
#define  min(A, B) ((A) < (B) ? (A) : (B))
#endif

#define IsOdd(x) (((unsigned) (x)) & 1)
#define IsEven(x) (! IsOdd (x))

/*** STRUCTURES AND DEFINED TYPES ***/

#define AUTO                                    /* C default storage class */
typedef char UNSIGNED_CHAR;                     /* for portability */
typedef unsigned BOOLEAN;                       /* use for YES/NO */
typedef int *POINTER;                           /* The generic pointer.  */
typedef int (*FUNC_PTR)();

/*** GLOBALS ***/

extern int errno;                           /* used by libnu for cmderr */

#endif  /* cdefs_ALREADY_INCLUDED */
