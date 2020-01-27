/*
OS.c - Cross paltform OS APIs
diStormX - The ultimate hooking library
https://github.com/gdabah/distormx
distorm at gmail dot com
Copyright (C) 2015-2020 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/

/*
 Heap isolation for hooks.
 OS module shouldn't use malloc/free but its own heap through OS_alloc/OS_free.
*/

#include <windows.h>
#include <TlHelp32.h>
#include "OS.h"


typedef struct {
	HANDLE hHeap;
} os_info_t;

static os_info_t g_osInfo;

typedef void * thread_t;

typedef struct {
	/* First round it's the TID (inside suspend function) and then an opened thread handle! */
	thread_t handle;
	/* IP of the thread to resume from. */
	void * ip;
} _ThreadInfo;

/* Structure to hold the state of suspended threads. */
typedef struct {
	/* Number of suspended threads. */
	unsigned int threadsCount;
	/* Maximum number of threads in the threads array. */
	unsigned int maxThreadsCount;
	/* Old priority of the calling thread, so we revert it later. */
	unsigned int oldThreadPriority;
	/* Array of thread infos. */
	_ThreadInfo threads[1];
} _ThreadsInfo;

/* Minimum start count of threads in the process, this grows by multiples of 2. */
#define START_THREADS_COUNT 64

int OS_init()
{
	g_osInfo.hHeap = HeapCreate(0, 0, 0);
	if (NULL == g_osInfo.hHeap) return FALSE;

	return TRUE;
}

void OS_destroy()
{
	if (NULL != g_osInfo.hHeap) {
		HeapDestroy(g_osInfo.hHeap);
		g_osInfo.hHeap = NULL;
	}
}

void * OS_alloc_code_page(void * target)
{
	int i;
	void * page;
	MEMORY_BASIC_INFORMATION mbi;
	SecureZeroMemory(&mbi, sizeof(mbi));

	/* Get current address' base allocation (it should be mapped). */
	if ((NULL != target) && !VirtualQuery((LPCVOID)target, &mbi, sizeof(mbi))) return FALSE;

	/* Try to allocate a page just next to it. */
	for (i = 1; i < MAXINT32; i *= 2) {
		/* Try lower address first. */
		page = VirtualAlloc((LPVOID)((size_t)mbi.AllocationBase - (i * OS_PAGE_SIZE)), OS_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		if (NULL != page) {
			return page; /* Assume page is zero'd. */
		}
		/* Try higher address next. */
		page = VirtualAlloc((LPVOID)((size_t)mbi.AllocationBase + mbi.RegionSize + (i * OS_PAGE_SIZE)), OS_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
		if (NULL != page) {
			return page; /* Assume page is zero'd. */
		}
	}

	return NULL;
}

void OS_free_page(void * address)
{
	VirtualFree(address, 0, MEM_RELEASE);
}

int OS_protect_page(void * address, unsigned int size, os_prot_t newProt, os_prot_t * oldProt)
{
	return VirtualProtect(address, size, newProt,  (PDWORD)oldProt) != FALSE;
	/* No need to translate oldProt, should be opaque to caller. */
}

int OS_is_page_committed(void * address)
{
	MEMORY_BASIC_INFORMATION mbi;
	SecureZeroMemory(&mbi, sizeof(mbi));

	if (NULL == address) return TRUE;

	/* Get current address' info. */
	if (!VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) return FALSE;

	return mbi.State == MEM_COMMIT;
}

int OS_suspend_threads(void ** threadsOpaque, unsigned int * threadsCount)
{
	int ret = FALSE;
	CONTEXT context;
	int suspendIndex = 0; /* Must be signed for cleanup code. */
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	_ThreadsInfo * threadsInfo = NULL;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	if (NULL == threadsOpaque) return FALSE;

	*threadsOpaque = NULL;
	*threadsCount = 0;

	/*
	 * Allocate threads info with some array size to begin with
	 * (64 threads should be ok inside a process, we will grow if necessary).
	 */
	threadsInfo = (_ThreadsInfo *)OS_realloc(NULL, sizeof(_ThreadsInfo) + START_THREADS_COUNT * sizeof(_ThreadInfo));
	if (NULL == threadsInfo) return FALSE;
	OS_memset(threadsInfo, 0, sizeof(_ThreadsInfo) + START_THREADS_COUNT * sizeof(_ThreadInfo));
	threadsInfo->maxThreadsCount = START_THREADS_COUNT;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == hSnap) goto cleanup;

	/* Boost priority so we're super fast and only then scan for other threads. */
	threadsInfo->oldThreadPriority = GetThreadPriority(GetCurrentThread());
	if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) goto cleanup;

	ret = Thread32First(hSnap, &te32);
	while (ret) {
		/* Gotta filter threads by their process id and not our own thread. */
		if ((te32.th32OwnerProcessID == GetCurrentProcessId()) && (te32.th32ThreadID != GetCurrentThreadId()))  {
			/* If no room to add the thread, then double the array. */
			if (threadsInfo->threadsCount + 1 == threadsInfo->maxThreadsCount) {
				threadsInfo = (_ThreadsInfo *)OS_realloc(threadsInfo, sizeof(_ThreadsInfo) + threadsInfo->maxThreadsCount * 2 * sizeof(_ThreadInfo));
				if (NULL == threadsInfo) goto cleanup;
				/* Update new max. */
				threadsInfo->maxThreadsCount *= 2;
			}
			/* Add the thread ID to the array. */
			threadsInfo->threads[threadsInfo->threadsCount++].handle = (thread_t)(size_t)te32.th32ThreadID;
		}
		ret = Thread32Next(hSnap, &te32);
	}
	CloseHandle(hSnap);
	hSnap = INVALID_HANDLE_VALUE;

	/* Gotta do another pass, so we don't deadlock with a suspended thread that has malloc's lock... */
	for (suspendIndex = 0; (unsigned int)suspendIndex < threadsInfo->threadsCount; suspendIndex++) {
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, (DWORD)(size_t)threadsInfo->threads[suspendIndex].handle);

		/*
		* Change the thread id to the handle of the thread.
		* Leave handle to the thread opened.
		*/
		threadsInfo->threads[suspendIndex].handle = hThread;
		if (NULL == hThread) {
			if (ERROR_INVALID_PARAMETER == GetLastError()) continue; /* Skip this thread, probably it died on us. */
			goto cleanup;
		}

		/* Suspend the thread! */
		if (-1 == SuspendThread(hThread)) {
			threadsInfo->threads[suspendIndex].handle = NULL;
			continue;
		}

		/* Get the IP address of the suspended thread. */
		context.ContextFlags = CONTEXT_CONTROL;
		if (!GetThreadContext(hThread, &context)) {
			threadsInfo->threads[suspendIndex].handle = NULL;
			continue;
		}

#if _M_IX86
		threadsInfo->threads[suspendIndex].ip = (void *)context.Eip;
#else
		threadsInfo->threads[suspendIndex].ip = (void *)context.Rip;
#endif
	}

	/* Success, we suspended all other threads. */
	*threadsOpaque = (void *)threadsInfo;
	if (NULL != threadsCount) *threadsCount = threadsInfo->threadsCount;

	ret = TRUE;

cleanup:
	if (INVALID_HANDLE_VALUE != hSnap) CloseHandle(hSnap);
	if (!ret) {
		/* Resume any suspended threads in case we failed. */
		while (suspendIndex >= 0) {
			HANDLE hThread = (HANDLE)threadsInfo->threads[suspendIndex].handle;
			if (NULL != hThread) {
				(void)ResumeThread(hThread);
				CloseHandle(hThread);
			}
			suspendIndex--;
		}

		/* Revert priority. */
		(void)SetThreadPriority(GetCurrentThread(), threadsInfo->oldThreadPriority);

		if (NULL != threadsInfo) OS_free(threadsInfo);
	}
	return ret;
}

void OS_resume_threads(void ** threadsOpaque)
{
	unsigned int i;
	CONTEXT context;
	_ThreadsInfo * threadsInfo;

	if ((NULL == threadsOpaque) || (NULL == *threadsOpaque)) return;

	threadsInfo = (_ThreadsInfo *)*threadsOpaque;
	for (i = 0; i < threadsInfo->threadsCount; i++) {
		HANDLE hThread = (HANDLE)threadsInfo->threads[i].handle;
		if (NULL == hThread) continue; /* Skip dead threads. */

		/* Try best effort to change IP. */
		context.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &context)) {
#if _M_IX86
			context.Eip = (DWORD)threadsInfo->threads[i].ip;
#else
			context.Rip = (DWORD64)threadsInfo->threads[i].ip;
#endif
			(void)SetThreadContext(hThread, &context);
		}
		(void)ResumeThread(hThread);
		CloseHandle(hThread);
	}

	/* Revert priority. */
	(void)SetThreadPriority(GetCurrentThread(), threadsInfo->oldThreadPriority);

	OS_free(threadsInfo);
	*threadsOpaque = NULL;
}

void * OS_get_thread_IP(void * threadsOpaque, unsigned int threadIndex)
{
	_ThreadsInfo * threadsInfo;
	if (NULL == threadsOpaque) return NULL;
	threadsInfo = (_ThreadsInfo *)threadsOpaque;
	if ((threadIndex >= 0) && (threadIndex < threadsInfo->threadsCount)) return threadsInfo->threads[threadIndex].ip;
	return NULL;
}

void OS_set_thread_IP(void * threadsOpaque, unsigned int threadIndex, void * ip)
{
	_ThreadsInfo * threadsInfo;
	if (NULL == threadsOpaque) return;
	threadsInfo = (_ThreadsInfo *)threadsOpaque;
	if ((threadIndex >= 0) && (threadIndex < threadsInfo->threadsCount)) threadsInfo->threads[threadIndex].ip = ip;
}

int OS_init_crit(OS_CRIT_SEC_OPAQUE * csOpaque)
{
	InitializeCriticalSection(csOpaque);
	return TRUE;
}

void OS_enter_crit(OS_CRIT_SEC_OPAQUE * csOpaque)
{
	EnterCriticalSection(csOpaque);
}

void OS_leave_crit(OS_CRIT_SEC_OPAQUE * csOpaque)
{
	LeaveCriticalSection(csOpaque);
}

void OS_delete_crit(OS_CRIT_SEC_OPAQUE * csOpaque)
{
	DeleteCriticalSection(csOpaque);
	SecureZeroMemory(csOpaque, sizeof(OS_CRIT_SEC_OPAQUE));
}

void * OS_malloc(size_t size)
{
	return HeapAlloc(g_osInfo.hHeap, 0, size);
}

void * OS_realloc(void * old, size_t size)
{
	if (NULL == old) { /* First time callers. */
		return OS_malloc(size);
	}

	return HeapReAlloc(g_osInfo.hHeap, HEAP_ZERO_MEMORY, old, size);
}

void OS_free(void * ptr)
{
	HeapFree(g_osInfo.hHeap, 0, ptr);
}

void * OS_memset(void * ptr, int c, size_t count)
{
	return memset(ptr, c, count);
}

void * OS_memcpy(void * dst, const void * src, size_t count)
{
	return memcpy(dst, src, count);
}

int OS_memcmp(const void * dst, const void * src, size_t count)
{
	return memcmp(dst, src, count);
}
