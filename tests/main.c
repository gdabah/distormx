/*
 * Tests distormx functionality.
 * More tests on a Windows platform.
 *
 */

 /* Comment out for testing on non-windows platforms. */
#define WIN_TESTABLE 1

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "../include/distormx.h"

#define _NOINLINE __declspec(noinline)

#ifdef WIN_TESTABLE
#include <Windows.h>
#endif


///////////////////////////////////

unsigned int (*g_orig_f1)(unsigned int, unsigned int) = NULL;

_NOINLINE unsigned int f1(unsigned int a, unsigned int b)
{
	printf("Orig: %d + %d: %d\n", a, b, a + b);
	return a + b;
}

_NOINLINE unsigned int f1_stub(unsigned int a, unsigned int b)
{
	printf("Hook start\n");
	/* Change behavior on purpose for testing's sake. */
	unsigned int ret = g_orig_f1(a + 1, b + 1);
	printf("Hook end\n\n");
	return ret;
}

/* Tests basic functionality. */
_NOINLINE void test1()
{
	unsigned int res = f1(1, 1);
	assert(res == 2);

	g_orig_f1 = f1;
	if (!distormx_hook((void**)&g_orig_f1, f1_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	/* This call is hooked, so it's really 3 + 3. */
	res = f1(2, 2);
	assert(res == 6);

	/* Calling directly. */
	res = g_orig_f1(7, 7);
	assert(res == 14);

	distormx_unhook((void*)&g_orig_f1);

	res = f1(4, 4);
	assert(res == 8);
}

/* Tests that unloading removes hooks. */
_NOINLINE void test2()
{
	unsigned int res = f1(1, 1);
	assert(res == 2);

	g_orig_f1 = f1;
	if (!distormx_hook((void**)&g_orig_f1, f1_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	/* This call is hooked, so it's really 3 + 3. */
	res = f1(2, 2);
	assert(res == 6);

	distormx_destroy();

	res = f1(4, 4);
	assert(res == 8);
}

/* Tests destroy_ex TRUE removes stubs. */
_NOINLINE void test3()
{
	bool success = false;
	unsigned int res = f1(1, 1);
	assert(res == 2);

	g_orig_f1 = f1;
	if (!distormx_hook((void**)&g_orig_f1, f1_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	/* This call is hooked, so it's really 3 + 3. */
	res = f1(2, 2);
	assert(res == 6);

	distormx_unhook((void*)&g_orig_f1);

	/* Calling stub after hook is removed is okay. */
	res = f1(4, 4);
	assert(res == 8);

	/* Specify TRUE to remove trampolines now! */
	distormx_destroy_ex(true);

	/* Stub should be gone and AV/segfault exception is thrown. */
#if WIN_TESTABLE
	__try
	{
		res = g_orig_f1(1, 1); /* This should raise! */
	}
	__except(true)
	{
		/* We caught an expected exception, that's good. */
		success = true;
	}
	assert(success);
#endif
}

///////////////////////////////////

void (*g_orig_f2)(char* s, int a, int b, int c, int d, int e, int f) = NULL;

_NOINLINE void f2(char* s, int a, int b, int c, int d, int e, int f)
{
	sprintf(s, "%s %d %d %d %d %d %d", "hello", a, b, c, d, e, f);
	printf("%s\n", s);
}

_NOINLINE void f2_stub(char* s, int a, int b, int c, int d, int e, int f)
{
	sprintf(s, "%s %d %d %d %d %d %d", "nope", a, b, c, d, e, f);
	printf("%s\n", s);
}

/* Tests many arguments in a hook/stub. */
_NOINLINE void test4()
{
	g_orig_f2 = f2;

	char buf[200] = { 0 };
	f2(buf, 0, 1, 2, 3, 4, 5);
	assert(!strcmp(buf, "hello 0 1 2 3 4 5"));

	if (!distormx_hook((void**)&g_orig_f2, f2_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	f2(buf, 0, 1, 2, 3, 4, 777);
	assert(!strcmp(buf, "nope 0 1 2 3 4 777"));
}

///////////////////////////////////

unsigned int (*g_orig_f3)(unsigned int) = NULL;
unsigned int (*g_orig_f4)(unsigned int) = NULL;
unsigned int (*g_orig_f5)(unsigned int) = NULL;

_NOINLINE unsigned int f3(unsigned int a)
{
	return a * 3;
}

_NOINLINE unsigned int f4(unsigned int a)
{
	return a * 4;
}

_NOINLINE unsigned int f5(unsigned int a)
{
	return a * 5;
}

_NOINLINE unsigned int f3_stub(unsigned int a)
{
	unsigned int ret = g_orig_f3(a) * 2; /* Change behavior by x 2. */
	return ret;
}

_NOINLINE unsigned int f4_stub(unsigned int a)
{
	unsigned int ret = g_orig_f4(a) * 2; /* Change behavior by x 2. */
	return ret;
}

_NOINLINE unsigned int f5_stub(unsigned int a)
{
	unsigned int ret = g_orig_f5(a) * 2; /* Change behavior by x 2. */

	return ret;
}

/* Tests that bulk hooking works. */
_NOINLINE void test5()
{
	distormx_begin_defer();

	g_orig_f3 = f3;
	if (!distormx_hook((void**)&g_orig_f3, f3_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	g_orig_f4 = f4;
	if (!distormx_hook((void**)&g_orig_f4, f4_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	g_orig_f5 = f5;
	if (!distormx_hook((void**)&g_orig_f5, f5_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	assert(f3(2) == 2 * 3);
	assert(f4(2) == 2 * 4);
	assert(f5(2) == 2 * 5);

	distormx_commit();

	assert(f3(2) == 2 * 3 * 2);
	assert(f4(2) == 2 * 4 * 2);
	assert(f5(2) == 2 * 5 * 2);

	distormx_destroy();
}

///////////////////////////////////

/* Tests that bulk hooking is canceled alright. */
_NOINLINE void test6()
{
	distormx_begin_defer();

	g_orig_f3 = f3;
	if (!distormx_hook((void**)&g_orig_f3, f3_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	g_orig_f4 = f4;
	if (!distormx_hook((void**)&g_orig_f4, f4_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	g_orig_f5 = f5;
	if (!distormx_hook((void**)&g_orig_f5, f5_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	assert(f3(2) == 2 * 3);
	assert(f4(2) == 2 * 4);
	assert(f5(2) == 2 * 5);

	distormx_abort_defer();

	/* Expect normal behavior here. */
	assert(f3(2) == 2 * 3);
	assert(f4(2) == 2 * 4);
	assert(f5(2) == 2 * 5);

	distormx_destroy();
}

///////////////////////////////////

unsigned int (*g_orig_f6)(unsigned int) = NULL;
unsigned int (*g_orig_f6_2)(unsigned int) = NULL;

_NOINLINE unsigned int f6(unsigned int a)
{
	return a * 6;
}

_NOINLINE unsigned int f6_stub(unsigned int a)
{
	/* Change behavior on purpose for testing's sake. */
	unsigned int ret = g_orig_f6(a * 2);
	return ret;
}

_NOINLINE unsigned int f6_stub_2(unsigned int a)
{
	/* Change behavior on purpose for testing's sake. */
	unsigned int ret = g_orig_f6(a * 2 * 2);
	return ret;
}

/* Tests that hooking same function twice works and it's chained. */
_NOINLINE void test7()
{
	assert(f6(10) == 60);

	g_orig_f6 = f6;
	if (!distormx_hook((void**)&g_orig_f6, f6_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	assert(f6(10) == 60 * 2);

	g_orig_f6_2 = f6;
	if (!distormx_hook((void**)&g_orig_f6_2, f6_stub_2)) {
		printf("Failed hooking");
		assert(false);
	}

	assert(f6(10) == 60 * 2 * 2);

	distormx_unhook(&g_orig_f6_2);
	assert(f6(10) == 60 * 2);

	distormx_unhook(&g_orig_f6);
	assert(f6(10) == 60);
}

///////////////////////////////////

#if WIN_TESTABLE

unsigned long g_test = 0;
BOOL g_running = true;
BOOL g_stubran = false; /* Have an indication that the threaded stub actually ran. */
#define THREADS_COUNT 4

void (*g_orig_f7)() = NULL;

_NOINLINE void f7()
{
	g_test++;
}

_NOINLINE void f7_stub()
{
	g_stubran = true;
	g_test += 2;
}

DWORD CALLBACK thread1(LPVOID p)
{
	p;

	/* Spin hard on calling f7. */
	while (g_running)
	{
		f7();
	}

	return 0;
}

/* Stress tests that hooking a function works in multi-threading. */
_NOINLINE void test8()
{
	HANDLE threads[THREADS_COUNT] = { 0 };
	for (unsigned int i = 0; i < THREADS_COUNT; i++)
	{
		threads[i] = CreateThread(NULL, 0, thread1, NULL, 0, NULL);
		assert(NULL != threads[i]);
		SetThreadAffinityMask(threads[i], (DWORD_PTR)1 << i);
	}

	g_orig_f7 = f7;
	if (!distormx_hook((void**)&g_orig_f7, f7_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	/* Let the threads use the new stub for a short while. */
	Sleep(400);
	/* The threads will quit now. */
	g_running = false;
	Sleep(100);

	distormx_destroy(true);

	assert(g_stubran == true);
}

#else

void test8()
{
	/* Pass. */
}

#endif

///////////////////////////////////

/* Stress tests multi-threading hooking. */
#if WIN_TESTABLE

void test9()
{
	/* Reset globals. */
	g_test = 0;
	g_running = true;
	g_stubran = false;

	HANDLE threads[THREADS_COUNT] = { 0 };
	for (unsigned int i = 0; i < THREADS_COUNT; i++)
	{
		threads[i] = CreateThread(NULL, 0, thread1, NULL, 0, NULL);
		assert(NULL != threads[i]);
		SetThreadAffinityMask(threads[i], (DWORD_PTR)1 << i);
	}

	for (unsigned int i = 0; i < 100; i++)
	{
		distormx_begin_defer();

		g_orig_f7 = f7;
		if (!distormx_hook((void**)&g_orig_f7, f7_stub)) {
			printf("Failed hooking");
			assert(false);
		}

		/* Now turn on the hook. */
		distormx_commit();

		distormx_unhook(&g_orig_f7);
	}

	/* The threads will quit now. */
	g_running = false;
	Sleep(100);

	distormx_destroy();

	assert(g_stubran == true);
}

#else

void test9()
{
	/* Pass. */
}

#endif

///////////////////////////////////

/* Stress tests that hooking a function works in multi-threading bulk hooking. */
#if WIN_TESTABLE

void test10()
{
	/* Reset globals. */
	g_test = 0;
	g_running = true;
	g_stubran = false;

	HANDLE threads[THREADS_COUNT] = { 0 };
	for (unsigned int i = 0; i < THREADS_COUNT; i++)
	{
		threads[i] = CreateThread(NULL, 0, thread1, NULL, 0, NULL);
		assert(NULL != threads[i]);
		SetThreadAffinityMask(threads[i], (DWORD)(1 << i));
	}

	distormx_begin_defer();

	g_orig_f7 = f7;
	if (!distormx_hook((void**)&g_orig_f7, f7_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	Sleep(50);
	/* Make sure stub hasn't run yet. */
	assert(g_stubran == false);

	/* Now turn on the hook. */
	distormx_commit();

	/* Let the threads use the new stub for a short while. */
	Sleep(400);
	/* The threads will quit now. */
	g_running = false;
	Sleep(100);

	distormx_destroy();

	assert(g_stubran == true);
}

#else

void test10()
{
	/* Pass. */
}

#endif

///////////////////////////////////

BOOL g_f8_called = false;

void f8()
{
	g_f8_called = true;
}

/*
 * Tests that hooking a function and a stub far away (at least 2gb difference) works.
 * Only relevant for x64 architecture, where we can have such a big distance in the address space.
 */
void test11()
{
#if WIN_TESTABLE && _WIN64

	/* Allocate our stub empty function ~3gb away from our current testing module in memory. */
	ULONG_PTR target = (ULONG_PTR)&test10 + (3000ULL * 1000000ULL);
	target &= -0x1000;
	LPVOID addr = (LPVOID)target;
	addr = VirtualAlloc(addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	assert(NULL != addr);

	*(unsigned char*)addr = 0xc3; /* RET instruction. */

	g_f8_called = false;
	f8();
	assert(g_f8_called == true);

	void (*g_orig_f8)() = f8;

	if (!distormx_hook((void**)&g_orig_f8, addr)) {
		printf("Failed hooking");
		assert(false);
	}

	g_f8_called = false;
	f8();
	/* Our stub doesn't call the original function this time. */
	assert(g_f8_called == false);

	distormx_destroy_ex(true);
	
	g_f8_called = false;
	f8();
	assert(g_f8_called == true);

#endif
}

///////////////////////////////////

char* (*g_orig_strcpy)(char* dst, const char* src) = NULL;

char* strcpy_stub(char* dst, char const * src)
{
	return g_orig_strcpy(dst, "hijacked");
}

/* Tests that import address table (IAT pointer lookup should be seamless) hooking works. */
void test12()
{
	g_orig_strcpy = strcpy;
	if (!distormx_hook((void**)&g_orig_strcpy, strcpy_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	char buf[100] = { 0 };
	strcpy(buf, "hello");
	assert(!strcmp(buf, "hijacked"));

	distormx_unhook(&g_orig_strcpy);
	strcpy(buf, "hello");
	assert(!strcmp(buf, "hello"));
}

///////////////////////////////////

/*
 * Tests RIP relative hooking works in first instructions of function.
 * Only relevant for x64 architecture.
 */
#if WIN_TESTABLE && _WIN64

void f9()
{
	printf("f9 here\n");
}

BOOL g_f9_stub_called = false;

void f9_stub()
{
	g_f9_stub_called = true;
	printf("f9 stub here\n");
}

void test13()
{
	LPVOID addr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	assert(NULL != addr);

	unsigned char buf[] = {0xff, 0x25, 0x01, 0x00, 0x00, 0x00, 0xcc }; /* JMP QWORD [RIP+0x1] */

	/* Copy an encoded RIP relative jump instruction to see that the hook is dealing with it alright. */
	memcpy(addr, buf, sizeof(buf)); /* Copy instruction. */
	*(DWORD_PTR*)((DWORD_PTR)addr + sizeof(buf)) = (DWORD_PTR)f9;

	void (*g_orig_f9)() = addr;

	if (!distormx_hook((void**)&g_orig_f9, f9_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	f9();
	assert(g_f9_stub_called == true);
	g_f9_stub_called = false;

	distormx_unhook(&g_orig_f9);

	f9();
	assert(g_f9_stub_called == false);
}

#else

void test13()
{
	/* Pass. */
}

#endif

///////////////////////////////////

void f10()
{
	printf("f10 here\n");
}

void f10_stub()
{
	printf("f10 stub here\n");
}


/* Tests trampolines page isn't RWX at leisure. */
void test14()
{
	bool RX = false;
	void (*orig_f10)() = f10;
	if (!distormx_hook((void**)&orig_f10, f10_stub)) {
		printf("Failed hooking");
		assert(false);
	}

	f10();

#if WIN_TESTABLE
	__try
	{
		*(unsigned char*)orig_f10 = 0xc3; /* Should fail. */
	}
	__except (1)
	{
		RX = true;
	}

	/* We are not supposed to be able to write on the RWX page. */
	assert(RX);
#endif

	distormx_destroy();
}

int main()
{
	printf("Test1 - basic functionality:\n");
	test1();
	printf("\nTest2 - destroy removes hooks:\n");
	test2();
	printf("\nTest3 - destroy(true) removes trampolines:\n");
	test3();

	printf("\nTest4 - a stub with 6 arguments:\n");
	test4();

	printf("\nTest5 - bulk hooking functionality:\n");
	test5();
	
	printf("\nTest6 - build hooking aborted:\n");
	test6();
	
	printf("\nTest7 - hooking same function twice:\n");
	test7();

	printf("\nTest8 - multi-threading hooking:\n");
	test8();

	printf("\nTest9 - multi-threading stress test:\n");
	test9();

	printf("\nTest10 - multi-threading bulk hooking:\n");
	test10();

	printf("\nTest11 - far away (2gb difference) hook:\n");
	test11();

	printf("\nTest12 - IAT hook:\n");
	test12();

	printf("\nTest13 - RIP relative hook:\n");
	test13();

	printf("\nTest14 - Verify trampolines page isn't RWX.\n");
	test14();

	return 0;
}
