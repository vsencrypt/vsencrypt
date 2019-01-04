//
// To avoid depend linux/mac.
// The source code can be compile on windows without cygwin
//

extern int opterr; /* = 1 */ /* if error message should be printed */
extern int optind; /* = 1 */ /* index into parent argv vector */
extern int optopt;           /* character checked for validity */
extern int optreset;         /* reset getopt */
extern char *optarg;         /* argument associated with option */
int getopt(int argc,
           char *const argv[],
           const char *optstring);
