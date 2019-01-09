#if defined(_MSC_VER)
const char *getpass(const char *prompt);
#else
#include <pwd.h>    // getpass()
#include <unistd.h> // getpass()
#endif
