#if defined(_MSC_VER)
#else
#include <pwd.h>    // getpass()
#include <unistd.h> // getpass()
#endif
