#include "stdafx.h"

// I cant remember this is from magazine from back in the day?

#if	M_I8086 || M_I286 || MSDOS	/* test Microsoft C definitions */
#define 	SWITCH	L'/'                     /* /: only used for DOS */
#else
#define 	SWITCH	L'-'                     /* -: always recognized */
#endif

/* ------------ EXPORT variables -------------------------------------- */

wchar_t *	optarg; 	/* option argument if : in opts */
int	optind = 1;			/* next argv index		*/
int	opterr = 1;			/* show error message if not 0	*/
int	optopt; 			/* last option (export dubious) */

						/* ------------ private section --------------------------------------- */

static	int sp = 1;			/* offset within option word	*/

static int badopt(wchar_t *name, wchar_t *text)
{
	if (opterr)			/* show error message if not 0	*/
		fwprintf(stderr, L"%s: %s -- %c", name, text, optopt);

	return (int) '?';               /* ?: result for invalid option */
}
/* ------------ EXPORT function --------------------------------------- */
int getopt(int argc, wchar_t **argv, wchar_t *opts)
{
	wchar_t *cp, ch;

	if (sp == 1)
	{
		if (argc <= optind || argv[optind][1] == L'\0')
			return EOF;	/* no more words or single '-'  */


		if ((ch = argv[optind][0]) != L'-' && ch != SWITCH)
			return EOF;	/* options must start with '-'  */

		if (!wcscmp(argv[optind], L"--"))
		{
			++optind;			/* to next word */
			return EOF;			/* -- marks end */
		}
	}

	optopt = (int)(ch = argv[optind][sp]);	/* flag option	*/

	if (ch == L':' || (cp = wcsrchr(opts, ch)) == NULL)
	{
		if (argv[optind][++sp] == L'\0')
		{
			++optind;	sp = 1; 	/* to next word */
		}

		return badopt(argv[0], L"illegal option");
	}

	if (*++cp == L':')             /* ':' option requires argument */
	{
		optarg = &argv[optind][sp + 1];	/* if same word */
		++optind;	sp = 1; 		/* to next word */

		if (*optarg == L'\0')                  /* in next word */
		{
			if (argc <= optind)		/* no more word */
				return badopt(argv[0], L"option requires an argument");

			optarg = argv[optind++];	/* to next word */
		}
	}
	else				/* flag option without argument */
	{
		optarg = NULL;

		if (argv[optind][++sp] == L'\0')
		{
			optind++;	sp = 1; 	/* to next word */
		}
	}

	return optopt;
}
