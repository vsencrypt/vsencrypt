#include <stdio.h>
#include <string.h>
#include "getpass.h"

#if _MSC_VER

#include <Windows.h>

#define _PASSWORD_LEN 128

static const char *_getpass(char *buf, size_t buf_nbytes)
{
	char *ret = fgets(buf, buf_nbytes, stdin);
	if (ret != NULL)
	{
		size_t len = strlen(buf);
		if (len >= 1 && buf[len - 1] == '\n')
		{
			// Remove tailing \n
			buf[len - 1] = 0;
		}
	}

	return ret;
}

const char *getpass(const char *prompt)
{
	char buf[_PASSWORD_LEN + 1] = {0};
	HANDLE h;
	DWORD mode = 0;

	if (prompt == NULL)
	{
		return NULL;
	}

	/* get stdin and mode */
	h = GetStdHandle(STD_INPUT_HANDLE);
	if (!GetConsoleMode(h, &mode))
	{
		return NULL;
	}

	if (!SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT))
	{
		return NULL;
	}

	printf("%s", prompt);
	fflush(stdout);
	const char *pass = _getpass(buf, _PASSWORD_LEN);

	/* reset echo */
	SetConsoleMode(h, mode);

	if (!pass)
	{
		return NULL;
	}

	return strdup(pass);
}

#endif
