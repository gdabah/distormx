#include <stdio.h>
#include "..\..\include\distormx.h"

unsigned int(*g_orig_f1)(unsigned int, unsigned int) = NULL;

__declspec(noinline) unsigned int f1(unsigned int a, unsigned int b)
{
	return printf("Orig: %d + %x: %d\n", a, b, a + b);
}

__declspec(noinline) unsigned int f2(unsigned int a, unsigned int b)
{
	printf("\nhook start\n");
	unsigned int ret = g_orig_f1(a, b);
	printf("hook end\n\n");
	return ret;
}

int main()
{
	f1(1, 1);

	g_orig_f1 = f1;
	if (!distormx_hook((void **)&g_orig_f1, f2)) {
		printf("failed hooking");
		return 1;
	}
	f1(2, 2);
	distormx_unhook((void *)&g_orig_f1);
	f1(3, 3);
	distormx_destroy();

	return 0;
}