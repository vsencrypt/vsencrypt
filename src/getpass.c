#include "getpass.h"

#if _MSC_VER

const char* getpass(const char* prompt)
{
	return prompt;
}

#endif
