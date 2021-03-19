/*
diStormX 1.0 - The ultimate hooking library
https://github.com/gdabah/distormx
distorm at gmail dot com
Copyright (C) 2015-2021 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.
*/


#ifndef DISTORMX_H
#define DISTORMX_H

/* Support C++ compilers */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * distormx_hook
 *
 * target - In/Out pointer that contains the function to hook.
 *          Returns a pointer to the trampoline of the original function.
 * stub   - In pointer of the function to call instead.
 * return value - int as bool, TRUE if succeeded.
 *
 * NOTES a. Hooking is deferred if distormx_begin_defer was previously called, until distormx_commit is called.
 *       b. If distormx_abort_defer was called all previous un/hooks in the batch will be removed.
 */
int distormx_hook(void ** target, void * stub);

/*
 * distormx_unhook
 *
 * prevTarget - In/Out pointer that was first passed to distormx_hook.
 *              If prevTarget is unknown it will ignore it silently.
 *              If function succeeded, prevTarget will contain NULL.
 * return value - none.
 *
 * NOTES a. Unhooking is deferred if distormx_begin_defer was previously called, until distormx_commit is called.
 *       b. If distormx_abort_defer was called all previous un/hooks in the batch will be removed.
 */
void distormx_unhook(void * prevTarget);

/*
 * distormx_begin_defer
 *
 * Instructs the hooking engine to begin a batch of multi hooks,
 * therefore all next calls to both distormx_hook and distormx_unhook will be deferred until committed.
 *
 * Once distormx_commit is called, all hooks/unhooks will be applied.
 * To cancel the batch, call distormx_abort_defer, which will remove all pending hooks.
 */
void distormx_begin_defer();

/*
 * distormx_abort_defer
 *
 * Removes all pending un/hook operations from the queue.
 * Resets status so next operation happens immediately.
 */
void distormx_abort_defer();

/*
 * distormx_commit
 *
 * Commits both pending hooks and unhooks in the current batch.
 *
 * Hooks all the queued functions at once.
 * The following steps are done:
 * 1) Preflight hooks to organize memory.
 * 2) Suspend all threads.
 * 3) Do actual hooks.
 * 4) Do actual unhooks, if any.
 * 5) Resume all threads.
 *
 * NOTE that the parameters to distormx_hook must still be valid at the time of committing.
 *
 * return value - int as bool, TRUE if everything succeeded.
 *
 * Side effects: defer is disabled.
 */
int distormx_commit();

/*
* allocator_callback_t
* A callback to allocate zero'd RX memory near target.
*
* targetVA - Pointer to target function that is going to be hooked.
*
* return value - Pointer to a newly allocated RX page.
*                         !!IMPORTANT NOTES!!:
*                a. The returned page must be zero'd initially.
*                b. It must be set as Read-Executable protection.
*                c. It must be maximum +-2GB away from target virtual address.
*                d. Must be using a correspondant APIs to the original implementation in os.c
*                   (e.g in Windows - VirtualAlloc/VirtualFree).
*                e. The page returned will be exhausted as much as possible.
*                f. NULL on failure, will cause failures on attempting the following hooking.
*/
typedef void * (*allocator_callback_t)(void * targetVA);

/*
* distormx_set_code_allocator
* Lets the user sets a proprietary read-exec page allocator near target address.
* Overrides default behavior, see OS.c!OS_alloc_code_page as an example.
* Will be called every time a new trampoline needs memory.
*
* callback - Callback of allocator_callback_t, see above expected behavior.
*            Pass NULL to go back to default behavior.
*
* return value - Previous callback (or NULL if wasn't set before).
*/
allocator_callback_t distormx_set_code_allocator(allocator_callback_t callback);

/*
 * distormx_destroy
 *
 * Tears down all hooks, structures and used memory.
 *
 * forceRemoval - Set to TRUE to remove ALL memory including trampolines.
 *                This is dangerous as some hooks might still be in use.
 *                By default it's set to FALSE.
 */
int distormx_destroy();
int distormx_destroy_ex(int forceRemoval);

#ifdef __cplusplus
} /* End Of Extern */
#endif

#endif /* DISTORMX_H */
