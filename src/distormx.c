/*
diStormX 0.9 - The ultimate hooking library for x86/x64
https://github.com/gdabah/distormx
distorm at gmail dot com
Copyright (C) 2015-2016 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.

Features:
 1) Support for both x86/x64
 2) Simple APIs and batch hook commit
 3) Low memory foot print, will re-use trampoline pages as much as possible
 4) RWX sensitive, will temporarily enable RWX and then revert to RX when writing trampolines
 5) Uses a private heap

TODOs:
 1) context per deferring mode?
 2) used APIs in OS.x should be protected (against other hooks)
 3) Unit Tests!!!
*/
 

#include "../include/distormx.h"
#include "OS.h"
#include "../distorm3/include/distorm.h"
#include "../distorm3/include/mnemonics.h"

#define X86_BRANCH_SIZE 5
#define X64_ABS_BRANCH_SIZE 14
#define MAX_TRAMPOLINE_SIZE 20 /* Max instruction sizes: 4 + 15 */
#define TRAMPOLINE_MAGIC 0xffffaa66
#define TRAMPOLINE_MAGIC_UNHOOKED 0xffffaa99

#define X86_CALL_OPCODE	0xe8
#define X86_JMP_OPCODE	0xe9

/* Structure that holds the actual jmp instruction (trampoline code should be application life time). */
typedef struct {
	/*
	 * Copied instructions from the target function we hook + a JMP to continue execution.
	 */
	unsigned char trampoline[MAX_TRAMPOLINE_SIZE];

#if _M_X64
	/*
	* In x64 if the target and the stub are too far from each other (>-/+2GB),
	* then a bridge is an absolute JMP instruction to the stub.
	* Note that the trampoline is allocated as close as possible to the target's page.
	*/
	unsigned char bridge[X64_ABS_BRANCH_SIZE];
#endif

	/* Magic value to validate trampoline. */
	unsigned int magic;

	/* Point back to the hook info. */
	void * hookInfo;
} trampoline_t;

#define MAX_TRAMPOLINES_PER_PAGE (OS_PAGE_SIZE / sizeof(trampoline_t))

/* Structure that describes a single hook info & state. */
typedef struct {
	/* Original bytes we patched, needed for unhooking. */
	unsigned char origBytes[X86_BRANCH_SIZE];

	/* Trampoline RX code.*/
	trampoline_t * code;

	/* Address of the target itself. */
	void * target;
} hook_info_t;

/* Structure that holds information for installing a hook, temporary only (should be on the stack). */
typedef struct {
	hook_info_t * info;
	_DInst insts[X86_BRANCH_SIZE];
	/* The next instruction the trampoline should go to after executing the copied instructions. */
	void * nextAddress;
	unsigned int trampolineSize;
	unsigned int instsCount;
} hook_info_ex_t;

/* An array of trampolines in the same virtual page. */
typedef struct {
	trampoline_t * trampolines;
	/* Number of trampolines in that page. */
	unsigned int trampolinesCount;
} page_info_t;

/* Type of deferred operation either hook or unhook. */
typedef enum { DX_DEFERRED_HOOK, DX_DEFERRED_UNHOOK } defer_type_e;

/* If the hooks are to be deferred, store minimum information to apply them later. */
typedef struct {
	void ** ppTarget;
	void * stub;
	void * preflightTarget;
	hook_info_t * hookInfo;
	defer_type_e deferType;
} defer_info_t;

/* Structure to hold all hooks related globals and the array of pages of trampolines. */
typedef struct {
	/* Array of trampolines pages. */
	page_info_t * pages;
	/* Number of pages allocated. */
	unsigned int pagesCount;

	/* Information of to-be-hooked. */
	defer_info_t * defers;
	unsigned int defersCount;
	int isDeferred;

	/* Information of to-be-unhooked. */
	hook_info_t ** unhookAddrs;
	unsigned int unhookAddrsCount;

	OS_CRIT_SEC_OPAQUE critSect;
	int initialized;

	/* allocator override for user's proprietary implementation, if NULL will call default implementation. */
	allocator_callback_t allocatorCallback;

	void * threadsOpaque;
	unsigned int threadsCount;
} hooks_globals_t;

static hooks_globals_t * distormx_globals()
{
	static hooks_globals_t globals; /* Zero'd. */
	return (hooks_globals_t *)&globals;
}

static page_info_t * distormx_alloc_page(void * target)
{
	page_info_t * pages;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return NULL;
	unsigned int pagesCount = globals->pagesCount;
	pages = (page_info_t *)OS_realloc(globals->pages, (pagesCount + 1) * sizeof(page_info_t));
	if (NULL == pages) return NULL;
	globals->pages = pages;

	/* Give a chance to user's callback for allocating the page. */
	if (NULL == globals->allocatorCallback) {
		globals->pages[pagesCount].trampolines = (trampoline_t *)OS_alloc_code_page(target);
	} else {
		globals->pages[pagesCount].trampolines = (trampoline_t *)globals->allocatorCallback(target);
	}
	if (NULL == globals->pages[pagesCount].trampolines) return NULL;
	globals->pages[pagesCount].trampolinesCount = 0;
	globals->pagesCount += 1;

	return &globals->pages[pagesCount];
}

static hook_info_t * distormx_alloc(void * target)
{
	trampoline_t * trampoline = NULL;
	hook_info_t * hookInfo = NULL;
	page_info_t * pageInfo = NULL;
	unsigned int i;

	ptrdiff_t wideTarget = (ptrdiff_t)target;
	ptrdiff_t diff;

	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return NULL;

	/* Find the nearest page we can use, basically required only for 64 bits. */
	for (i = 0; i < globals->pagesCount; i++) {
		diff = wideTarget - (ptrdiff_t)globals->pages[i].trampolines;
		if ((diff <= MAXINT32) && (diff > MININT32)) {
			pageInfo = &globals->pages[i];
		}
	}

	/*
	 * If we didn't find a relevant page, allocate a new one then.
	 * In case we found a page, make sure it's not full.
	 */
	if ((NULL == pageInfo) || (pageInfo->trampolinesCount >= MAX_TRAMPOLINES_PER_PAGE)) {
		pageInfo = distormx_alloc_page(target);
		if (NULL == pageInfo) return NULL;
	}

	hookInfo = OS_malloc(sizeof(hook_info_t));
	if (NULL == hookInfo) {
		/* Note: if distorm_alloc_page was called, it will be freed in destroy eventually. */
		return NULL;
	}

	trampoline = (trampoline_t*)((unsigned char *)pageInfo->trampolines + (pageInfo->trampolinesCount * sizeof(trampoline_t)));
	pageInfo->trampolinesCount += 1;

	hookInfo->code = trampoline;

	return hookInfo;
}

static void * distormx_follow_target(void * target)
{
	unsigned char * p = (unsigned char *)target;
	if (*p == 0xe9) {
		return distormx_follow_target((void *)((ptrdiff_t)target + 5 + *(int*)(p + 1)));
	} if (*p == 0xeb) {
		return distormx_follow_target((void *)((ptrdiff_t)target + 2 + *(char*)(p + 1)));
	}
#if _M_IX86
	else if ((*p == 0xff) && (*(p + 1) == 0x25)) {
		return distormx_follow_target(**(void ***)(p + 2));
	}
#else /* _M_X64 */
	else if ((*p == 0xff) && (*(p + 1) == 0x25)) {
		/* JMP QWORD [RIP + offset] */
		int off = *(int*)(p + 2);
		return distormx_follow_target(*(void **)((ptrdiff_t)target + off + 6));
	}
	else if ((*p == 0x48) && (*(p + 1) == 0xff) && (*(p + 2) == 0x25)) {
		int off = *(int*)(p + 3);
		return distormx_follow_target(*(void **)((ptrdiff_t)target + off + 7));
	}
#endif
	return target;
}

static void distormx_connect_stub(void * source, void * target, unsigned char * bridgeCode, hook_info_t * hookInfo)
{
	ptrdiff_t iSource = (ptrdiff_t)source;
	ptrdiff_t iTarget = (ptrdiff_t)target;
	ptrdiff_t diff = iTarget - iSource - 5;

	bridgeCode[0] = X86_JMP_OPCODE;

#if _M_IX86
	*(unsigned int*)&bridgeCode[1] = (unsigned int)diff;
	hookInfo; /* Unreferenced. */
#elif _M_X64
	/* See if we could use a single branch from the hooked function to the stub. */
	if ((diff > MAXINT32) || (diff <= MININT32)) {
		/*
		 * We are going to need a bridge through hookInfo->bridge.
		 * Bridge is required because the target address and the stub are too far from each (more than 31 bits).
		 *
		 * Emit:
		 * JMP QWORD [RIP+0]
		 * DQ <ABS_ADDR>
		 */
		hookInfo->code->bridge[0] = 0xff;
		hookInfo->code->bridge[1] = 0x25;
		*(unsigned int*)&hookInfo->code->bridge[2] = 0;
		*(void **)&hookInfo->code->bridge[6] = target;

		/* Update the relative offset to point to the bridge instead. */
		diff = (ptrdiff_t)hookInfo->code->bridge - iSource - 5;
	}

	*(unsigned int*)&bridgeCode[1] = (unsigned int)diff;
#endif
}

static int distormx_disasm(void * address, hook_info_ex_t * hookInfoEx)
{
	_CodeInfo ci;
	ci.code = (uint8_t *)address;
	ci.codeLen = 64;
	ci.codeOffset = (_OffsetType)address;
#if _M_IX86
	ci.dt = Decode32Bits;
#else
	ci.dt = Decode64Bits;
#endif
	ci.features = DF_NONE;
	distorm_decompose(&ci, hookInfoEx->insts, X86_BRANCH_SIZE, &hookInfoEx->instsCount);
	return hookInfoEx->instsCount > 0;
}

static int distormx_copy_and_relocate_instruction(_DInst * inst, hook_info_ex_t * hookInfoEx)
{
	_OffsetType target = 0;
	unsigned char * code;

	/* Make sure we got enough room to copy the instruction. */
	if (hookInfoEx->trampolineSize + inst->size > MAX_TRAMPOLINE_SIZE) return FALSE;
	/*
	 * Since we might create new instruction because of relocations,
	 * we will have to keep track of the real address we have to continue from.
	 */
	hookInfoEx->nextAddress = (void *)((size_t)hookInfoEx->nextAddress + inst->size);

	/* See if some instructions need special relocation treatment. */
	if ((inst->opcode == I_CALL) && (inst->ops[0].type == O_PC)) {
		ptrdiff_t diff;
		/* Is it a relative call? Any other call instruction should be copied as is (E.G. CALL EAX). */
		/* Calculate target. */
		target = INSTRUCTION_GET_TARGET(inst);
		/* Emit a new instruction with the corrected relative target address. */
		code = &hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize];

#if _M_X64
		/* Validate range in x64 or die. */
		diff = (ptrdiff_t)target - (ptrdiff_t)code - 5;
		if ((diff > MAXINT32) || (diff <= MININT32)) return FALSE;
#else
		diff; /* Unreferenced. */
#endif

		*code = X86_CALL_OPCODE;
		*(unsigned int *)(code + 1) = (unsigned int)((ptrdiff_t)target - (ptrdiff_t)code - 5);
		hookInfoEx->trampolineSize += 5;
	} else {
		/* Copy instruction as is. */
		OS_memcpy(&hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize], (const void *)((size_t)inst->addr), inst->size);
		hookInfoEx->trampolineSize += inst->size;

#if _M_X64
		/*
		 * In x64 an instruction can be RIP relative.
		 * So it only means we will have to copy it and fix the relativity.
		 * The problem is that the it might happen that the copied instruction
		 * will get too far away from the RIP relative target address.
		 * However, it should be really rare since we allocated a page close to the hooked address.
		 * In case it ever happens we could always build better instruction chains to overcome this.
		 *
		 * The nice thing about RIP relative is that the offset is always signed 32 bits displacement.
		 * Thanks Intel for putting displacements just before immediates thus we can find it and patch it easily.
		 * And that's why we don't care which instruction we patch, nothing needs a special treatment.
		 */
		if (inst->flags & FLAG_RIP_RELATIVE) {
			ptrdiff_t diff;
			unsigned int i;
			unsigned int immSize = 0;
			target = INSTRUCTION_GET_RIP_TARGET(inst);
			/* Validate range or die. */
			diff = ((ptrdiff_t)target - (ptrdiff_t)(hookInfoEx->info->code->trampoline + hookInfoEx->trampolineSize));
			if ((diff > MAXINT32) || (diff <= MININT32)) return FALSE;
			/* Skip the immediate, if one exists, so we reach to the displacement. */
			for (i = 0; i < OPERANDS_NO; i++) {
				if (inst->ops[i].type == O_IMM) {
					immSize = inst->ops[i].size / 8;
					break;
				}
			}
			/* Fix the relative offset (start from end of instruction, 4 = size of disp plus immSize). */
			*(unsigned int*)&hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize - immSize - 4] = (unsigned int)diff;
		}
#endif
	}
	return TRUE;
}

static int distormx_copy_instructions(hook_info_ex_t * hookInfoEx)
{
	unsigned int i;
	unsigned int instsSize = 0;
	unsigned int meta;

	/*
	 * We keep track of the real address to continue trampoline from.
	 * This might become necessary if we don't copy the instructions 1 to 1.
	 */
	hookInfoEx->nextAddress = (void *)((size_t)hookInfoEx->insts[0].addr);

	/* Scan all instructions and see if we could patch them. */
	for (i = 0; ((i < X86_BRANCH_SIZE) && (i < hookInfoEx->instsCount)); i++) {
		if (hookInfoEx->insts[i].flags == FLAG_NOT_DECODABLE) return FALSE;

		meta = META_GET_FC(hookInfoEx->insts[i].meta);

		/* If it's any INTxx or JMP instruction, just fail. */
		/* TODO: handle branches smarter. */
		/* BUGBUGBUG: In some cases there's false positive on 55 instruction (push ebp). Disabled for now */
		//if ((meta == FC_INT) || (meta == FC_UNC_BRANCH) || (meta == FC_CND_BRANCH)) return FALSE;

		if (!distormx_copy_and_relocate_instruction(&hookInfoEx->insts[i], hookInfoEx)) return FALSE;

		instsSize += hookInfoEx->insts[i].size;
		/* Check if we're done copying instructions. */
		if (instsSize >= X86_BRANCH_SIZE) {
			/* Emit the JMP instruction at the end of the copied instructions to continue at the next instruction. */
			ptrdiff_t iSource = (ptrdiff_t)&hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize];
			ptrdiff_t iTarget = (ptrdiff_t)hookInfoEx->nextAddress;
			hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize] = X86_JMP_OPCODE;
			*(unsigned int*)&hookInfoEx->info->code->trampoline[hookInfoEx->trampolineSize + 1] = (unsigned int)(iTarget - iSource - 5);
			return TRUE;
		}
		/* If instruction is RET family, then fail. BTW - it's ok to patch RET too if we have sufficient room. */
		if (meta == FC_RET) break;
	}

	/* If we reached here it means we didn't have enough bytes to write our patch. */
	return FALSE;
}

static defer_info_t * distormx_alloc_defer_info()
{
	defer_info_t * currDefer, *defers;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return NULL;
	defers = (defer_info_t *)OS_realloc(globals->defers, (globals->defersCount + 1) * sizeof(defer_info_t));
	if (NULL == defers) return NULL;
	globals->defers = defers;

	currDefer = (defer_info_t *)((size_t)globals->defers + globals->defersCount * sizeof(defer_info_t));
	OS_memset(currDefer, 0, sizeof(defer_info_t));
	globals->defersCount += 1;

	return currDefer;
}

static int distormx_patch(void * target, void * code, unsigned int codeLength, hook_info_ex_t * hookInfoEx, int shouldSuspend, int isHooking)
{
	unsigned int oldProt;
	unsigned int i;
	void * threadsOpaque;
	unsigned int threadsCount;
	int retVal = FALSE;
	/*
	 * If we are not going to suspend here, since everything is suspended already in deferring mode,
	 * then we have to use the global threads state of the distormx_commit function.
	 */
	if (NULL == distormx_globals()) return FALSE;

	threadsOpaque = distormx_globals()->threadsOpaque;
	threadsCount = distormx_globals()->threadsCount;

	/* Only suspend other threads if we have to. */
	if (!shouldSuspend || OS_suspend_threads(&threadsOpaque, &threadsCount)) {
		/* Change protection to page so we could patch it. */
		if (!OS_protect_page(target, codeLength, OS_PAGE_RWX, &oldProt)) {
			if (shouldSuspend) {
				OS_resume_threads(&threadsOpaque);
			}
			return FALSE;
		}
		/* See if any thread's IP is inside the patched range, only possible during hooking. */
		if (isHooking) {
			for (i = 0; i < threadsCount; i++) {
				size_t ip = (size_t)OS_get_thread_IP(threadsOpaque, i);

				/* See if the IP is in the range. */
				if ((ip >= (size_t)target) && (ip < (size_t)target + X86_BRANCH_SIZE)) {
					/*
					* Now move it to the trampoline.
					* It's ok to move it relatively because we copy 1 to 1 so far.
					* In the future we might need to check the mapping...
					* Rebase it:
					*/
					ip -= (size_t)target;
					ip += (size_t)hookInfoEx->info->code->trampoline;
					OS_set_thread_IP(threadsOpaque, i, (void *)ip);
				}
			}
		}

		/* Patch the function's code at last. */
		OS_memcpy(target, code, codeLength);

		/* Return page to original protection. */
		retVal = OS_protect_page(target, codeLength, oldProt, &oldProt) != FALSE;
		/* Resume threads. */
		if (shouldSuspend) (void)OS_resume_threads(&threadsOpaque);
	}

	return retVal;
}

static int distormx_init()
{
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return FALSE;

	if (!OS_init()) return FALSE;

	if (!OS_init_crit(&globals->critSect)) {
		OS_destroy();
		return FALSE;
	}

	/* Note isDeferred could be 1 already here since distormx_begin_defer could've been called. */

	globals->initialized = TRUE;
	return TRUE;
}

static int distormx_hook_internal(void ** ppTarget, void * stub, defer_info_t * deferredInfo)
{
	int shouldSuspend = TRUE;
	int ret = FALSE;
	void * target;
	hook_info_t * hookInfo;
	/* Extra information needed to create the trampoline but not for hook's life time. */
	hook_info_ex_t hookInfoEx;
	SecureZeroMemory(&hookInfoEx, sizeof(hookInfoEx));

	/* Follow in target address to skip branches. */
	target = distormx_follow_target(*ppTarget);

	/* In deferring mode we must not allocate memory, so we have to use existing hookInfo. */
	if (NULL != deferredInfo) {
		/* Use the preflight hook info! */
		hookInfo = deferredInfo->hookInfo;
		/*
		 * We gotta make sure targets haven't changed.
		 * If they did then it means another thread hooked the function or something happened with it.
		 * Technically, if the target got changed, and points to a far away page, we might need to allocate a new page.
		 * In deferred mode we must not allocate memory.
		 * Therefore, we rather fail miserably in both x86/x64!
		 */
		if (deferredInfo->preflightTarget != target) return FALSE;

		/* Mark that we shouldn't suspend other threads as they are already suspended. */
		shouldSuspend = FALSE;
	} else {
		/* Allocate a new trampoline for this hook. */
		hookInfo = distormx_alloc(target);
		if (NULL == hookInfo) return FALSE;
	}

	hookInfoEx.info = hookInfo;
	/* Disassemble the first few instructions. */
	if (distormx_disasm(target, &hookInfoEx)) {

		os_prot_t oldProt;
		/* Make trampoline's page temporarily RWX. */
		if (OS_protect_page(&hookInfo->code->trampoline, MAX_TRAMPOLINE_SIZE, OS_PAGE_RWX, &oldProt)) {

			/* Copy enough instructions to the trampoline and relocate (fix) offsets too. */
			if (distormx_copy_instructions(&hookInfoEx)) {

				unsigned char bridgeCode[X86_BRANCH_SIZE];

				/*
				 * Build the JMP instruction from the hooked function to the stub,
				 * might need a bridge in x64 if target/stub are more than -/+2GB.
				 */
				distormx_connect_stub(target, stub, bridgeCode, hookInfo);

				/* Some unhooking book keeping. */
				OS_memcpy(hookInfo->origBytes, target, X86_BRANCH_SIZE);
				hookInfo->target = target;
				hookInfo->code->magic = TRAMPOLINE_MAGIC;
				hookInfo->code->hookInfo = (void *)hookInfo;

				/* FIRST! Set output argument to contain trampoline address, so hook stub can work immediately. */
				*ppTarget = (void *)hookInfo->code->trampoline;

				ret = distormx_patch(target, bridgeCode, X86_BRANCH_SIZE, &hookInfoEx, shouldSuspend, TRUE) != FALSE;
				/* Did we fail installing the hook? */
				if (!ret) {
					*ppTarget = NULL;
					/* To keep things simple, we will just mark this hook as dud. Can't release memory in case we're in deferring mode. */
					hookInfo->code->magic = TRAMPOLINE_MAGIC_UNHOOKED;
				}
			}
			OS_protect_page(&hookInfo->code->trampoline, MAX_TRAMPOLINE_SIZE, oldProt, &oldProt);
		}
	}

	return ret;
}

int distormx_hook(void ** ppTarget, void * stub)
{
	int ret;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return FALSE;

	/* Input validation. */
	if ((NULL == ppTarget) || (NULL == *ppTarget) || (NULL == stub)) return FALSE;

	if (!globals->initialized)
		if (!distormx_init()) return FALSE;

	OS_enter_crit(&globals->critSect);

	/* See if the hook should be deferred, so we keep it for later. */
	if (globals->isDeferred) {
		defer_info_t * deferInfo;
		deferInfo = distormx_alloc_defer_info();
		if (NULL == deferInfo) {
			OS_leave_crit(&globals->critSect);
			return FALSE;
		}

		deferInfo->ppTarget = ppTarget;
		deferInfo->stub = stub;
		deferInfo->deferType = DX_DEFERRED_HOOK;

		OS_leave_crit(&globals->critSect);
		return TRUE;
	}

	/* Do the hook now. */
	ret = distormx_hook_internal(ppTarget, stub, NULL);
	OS_leave_crit(&globals->critSect);
	return ret;
}

static void distormx_unhook_internal(hook_info_t * hookInfo, int shouldSuspend)
{
	/* Validate again now that we got the crit. */
	if (hookInfo->code->magic == TRAMPOLINE_MAGIC) {
		/* Validate hook is still going to our stub, so we can unhook. Otherwise we gotta fail. */
		// BUGBUG fix bridgecode comparison && (OS_memcmp(hookInfo->target, hookInfo->bridgeCode, X86_BRANCH_SIZE) == 0)
		if (OS_is_page_committed(hookInfo->target)) {
			/* Other threads are suspended inside the patching function. */
			(VOID)distormx_patch(hookInfo->target, hookInfo->origBytes, sizeof(hookInfo->origBytes), NULL, shouldSuspend, FALSE);
		}

		os_prot_t oldProt;
		/* Make trampoline's page temporarily RWX. */
		if (OS_protect_page(&hookInfo->code->magic, sizeof(unsigned int), OS_PAGE_RWX, &oldProt)) {
			/* Mark it's unhooked. */
			hookInfo->code->magic = TRAMPOLINE_MAGIC_UNHOOKED;
			hookInfo->code->hookInfo = NULL;
			OS_protect_page(&hookInfo->code->trampoline, MAX_TRAMPOLINE_SIZE, oldProt, &oldProt);
		}

		OS_free(hookInfo);
	}
}

void distormx_unhook(void * prevTarget)
{
	trampoline_t * trampoline;
	hook_info_t * info;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return;

	if (!globals->initialized) return;

	if ((NULL == prevTarget) || (NULL == *(void**)prevTarget)) return;
	trampoline = *(trampoline_t **)prevTarget;

	/*
	 * It might happen that distormx_commit failed, and then later unhook is called anyways.
	 * So next thing is that info points to the supposed-to-be-hooked function (instead of a trampoline).
	 * In addition, usually it's in unloading code, and thus if they tried to hook a DLL, and it's unloaded,
	 * the following magic test will segfault too.
	 * Therefore, extra precaution must be done.
	 */
	if (!OS_is_page_committed(trampoline)) return;

	/* Hold it first, so no double unhooking somehow. */
	OS_enter_crit(&globals->critSect);

	/* Validate given prevTarget is ours. */
	if (trampoline->magic != TRAMPOLINE_MAGIC) {
		OS_leave_crit(&globals->critSect);
		return;
	}

	info = trampoline->hookInfo;

	if (globals->isDeferred) {
		/* Allocate extra room for the pointer to the trampoline, so we can unhook it later. */
		hook_info_t ** unhookAddrs = (hook_info_t **)OS_realloc(globals->unhookAddrs, (globals->unhookAddrsCount + 1) * sizeof(hook_info_t *));
		if (NULL == unhookAddrs) {
			OS_leave_crit(&globals->critSect);
			return;
		}
		globals->unhookAddrs = unhookAddrs;
		globals->unhookAddrs[globals->unhookAddrsCount] = info;
		globals->unhookAddrsCount += 1;
	} else {
		distormx_unhook_internal(info, TRUE); /* Suspend threads. */
	}

	/* NOTE! When unhooking we must keep trampoline in case somebody may still return to it. */

	OS_leave_crit(&globals->critSect);
}

void distormx_begin_defer()
{
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return;

	/* It's ok if distormx_init wasn't called yet. */

	globals->isDeferred = TRUE;
}

void distormx_abort_defer()
{
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return;

	/* Remove all deferred hooks that weren't installed. Their hookInfo's will be freed later. */
	globals->isDeferred = FALSE;
	if (globals->defersCount) {
		OS_free(globals->defers);
		globals->defers = NULL;
		globals->defersCount = 0;
	}

	/* Removed all deferred unhooks. Going to unhook everything soon anyway. */
	if (globals->unhookAddrsCount) {
		OS_free(globals->unhookAddrs);
		globals->unhookAddrs = NULL;
		globals->unhookAddrsCount = 0;
	}
}

int distormx_commit()
{
	unsigned int i;
	int ret = FALSE;

	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return FALSE;
	if (!globals->initialized) return FALSE;
	if (!globals->isDeferred) return FALSE;

	/* Disable deferred anyway. */
	globals->isDeferred = FALSE;

	if (!globals->defersCount && !globals->unhookAddrsCount) return FALSE;

	OS_enter_crit(&globals->critSect);
	
	/* Preflight, make one pass to allocate trampolines for all deferred hooks first. */
	for (i = 0; i < globals->defersCount; i++) {
		/* Follow in target address to skip branches. */
		void * target = distormx_follow_target(*globals->defers[i].ppTarget);

		/* Allocate a new trampoline for this hook. */
		hook_info_t * hookInfo = distormx_alloc(target);
		if (NULL == hookInfo) goto cleanup;

		/*
		 * Store some info.
		 * Since we do preflight, we want to make sure nobody touches the
		 * target address between the time we did the preflight and the time we suspended other threads.
		 */
		globals->defers[i].preflightTarget = target;
		globals->defers[i].hookInfo = hookInfo;
	}

	/* Now suspend all other threads only once. */
	if (!OS_suspend_threads(&globals->threadsOpaque, &globals->threadsCount)) goto cleanup;

	/* Walk over the deferred hooks and apply them with the previously allocated hookInfo. */
	for (i = 0 ; i < globals->defersCount; i++)
		if ((ret = distormx_hook_internal(globals->defers[i].ppTarget, globals->defers[i].stub, &globals->defers[i])) == FALSE) break;

	/* Do all deferred unhooks now. */
	for (i = 0; i < globals->unhookAddrsCount; i++)
		distormx_unhook_internal(globals->unhookAddrs[i], FALSE); /* Don't suspend. */

	/* Resume threads. */
	(void)OS_resume_threads(&globals->threadsOpaque);

cleanup:
	if (NULL != globals->defers) OS_free(globals->defers);
	globals->defers = NULL;
	globals->defersCount = 0;

	if (NULL != globals->unhookAddrs) OS_free(globals->unhookAddrs);
	globals->unhookAddrs = NULL;
	globals->unhookAddrsCount = 0;

	OS_leave_crit(&globals->critSect);
	return ret;
}

allocator_callback_t distormx_set_code_allocator(allocator_callback_t callback)
{
	allocator_callback_t prev;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return NULL;

	prev = globals->allocatorCallback;
	globals->allocatorCallback = callback;
	return prev;
}

int distormx_destroy()
{
	/* By default we leave trampolines in memory, this is much safer. */
	return distormx_destroy_ex(FALSE);
}

int distormx_destroy_ex(int forceRemoval)
{
	unsigned int i, j;
	hooks_globals_t * globals = distormx_globals();
	if (NULL == globals) return FALSE;
	if (!globals->initialized) return FALSE;

	OS_enter_crit(&globals->critSect);
	globals->initialized = FALSE;

	distormx_abort_defer();

	/*
	 * Unhook all.
	 * Now suspend all other threads only once (instead of per un/hook). Try to do our best, hopefully we manage to suspend.
	 */
	if (globals->pagesCount && OS_suspend_threads(&globals->threadsOpaque, &globals->threadsCount)) {
		for (i = 0; i < globals->pagesCount; i++) {
			if (globals->pages[i].trampolinesCount) {
				for (j = 0;
					((j < MAX_TRAMPOLINES_PER_PAGE) && (globals->pages[i].trampolines[j].magic != 0));
					j++)
				{
					hook_info_t * hookInfo = globals->pages[i].trampolines[j].hookInfo;
					if (NULL != hookInfo) {
						distormx_unhook_internal(hookInfo, FALSE); /* Don't suspend threads as we did already. */
					}
				}

				if (forceRemoval) {
					/* Remove actual pages of trampolines, this is dangerous in case some hooks are still used! */
					OS_free_page(globals->pages[i].trampolines);
				}
				globals->pages[i].trampolines = NULL;
				globals->pages[i].trampolinesCount = 0;
			}
		}

		/* Resume threads. */
		(void)OS_resume_threads(&globals->threadsOpaque);
	}

	/* Free globals. */
	OS_free(globals->pages);
	globals->pages = NULL;
	globals->pagesCount = 0;

	OS_leave_crit(&globals->critSect);
	OS_delete_crit(&globals->critSect);

	OS_destroy();

	return TRUE;
}
