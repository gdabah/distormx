/*
diStormX - The ultimate hooking library
https://github.com/gdabah/distormx
distorm at gmail dot com
Copyright (C) 2015-2020 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/


#ifndef OS_H
#define OS_H

/* Currently this module supports only Windows. */
#include <windows.h>

/* In case someone doesn't have these definitions. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif


/* // Typedefs that are OS dependent // */

#define OS_PAGE_SIZE	0x1000
#define OS_PAGE_RWX		PAGE_EXECUTE_READWRITE
#define OS_PAGE_RX		PAGE_EXECUTE_READ
typedef CRITICAL_SECTION OS_CRIT_SEC_OPAQUE;
typedef unsigned int os_prot_t;

/* // Values that must be in sync with page_alloc_type_e!distormx.h // */
#define OS_PAGEALLOCSTRATEGY_UP   0
#define OS_PAGEALLOCSTRATEGY_DOWN 1
#define OS_PAGEALLOCSTRATEGY_IMPL 2

/* // General OS // */
int OS_init();
void OS_destroy();

/* // Virtual Memory // */

/* Allocate a page as near as possible to target's address. Useful in x64. */
void * OS_alloc_code_page(void * target);
/* Free a page that was allocated previously with OS_alloc_page. */
void OS_free_page(void * address);
/* Change the protection of a page, returns the oldProt, use OS_PAGE_XXX flags. Returns TRUE if succeeded. */
int OS_protect_page(void * address, unsigned int size, os_prot_t newProt, os_prot_t * oldProt);
/* Returns TRUE if page exists. */
int OS_is_page_committed(void * address);

/* // Threading // */

/*
 * Boost priority of current thread and suspend the rest of the threads in the process.
 * A matching call to OS_resume_threads must occur ASAP.
 * threadsOpaque holds an allocated memory.
 * threadsCount will contain the number of suspended threads.
 * Returns TRUE if succeeded.
 * If fails, it exits clean (so no thread is suspended).
 */
int OS_suspend_threads(void ** threadsOpaque, unsigned int * threadsCount);

/*
 * Resumes all threads that OS_suspend_threads suspended in the first place.
 * Releases threadsOpaque's memory.
 * Reverts calling thread's priority.
 * The caller thread must be the same one that called OS_suspend_threads.
 */
void OS_resume_threads(void ** threadsOpaque);

/* Gets the IP register value of a given suspended thread. */
void * OS_get_thread_IP(void * threadsOpaque, unsigned int threadIndex);

/* Sets the IP register value of a given suspended thread. */
void OS_set_thread_IP(void * threadsOpaque, unsigned int threadIndex, void * ip);


/* // Critical Section // */

/* Initialize an OS dependent opaque crit-sect structure. */
int OS_init_crit(OS_CRIT_SEC_OPAQUE * csOpaque);
/* Enter given (initialized) crit-sect. */
void OS_enter_crit(OS_CRIT_SEC_OPAQUE * csOpaque);
/* Leave given (initialized) crit-sect. */
void OS_leave_crit(OS_CRIT_SEC_OPAQUE * csOpaque);
/* Delete given (initialized) crit-sect. */
void OS_delete_crit(OS_CRIT_SEC_OPAQUE * csOpaque);


/* // Generic CRT functions // */
void * OS_malloc(size_t size);
void * OS_realloc(void * old, size_t size);
void OS_free(void * ptr);
void * OS_memset(void * ptr, int c, size_t count);
void * OS_memcpy(void * dst, const void * src, size_t count);
int OS_memcmp(const void * dst, const void * src, size_t count);

#endif /* OS_H */
