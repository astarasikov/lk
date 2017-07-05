#include <stdio.h>
#include <string.h>

#define KASAN_SHADOW_OFFSET 0xd0000000
#define __always_inline inline

#define LK_DEBUG_KASAN_GLOBALS 0

static inline void kasan_report(
		unsigned long addr,
		size_t size,
		bool write,
		unsigned long ret_ip)
{
	if (addr == 112301) {
		asm volatile ("smc #42");
	}

	//TODO(astarasikov): this can backfire horribly
	//if printf or UART routines trigger KASAN themselves
	//but so far this has not happened
	printf("%s: addr=%lx size=%d pc=%lx\n", __func__, addr, size, ret_ip);
}

/******************************************************************************
 * Macro definitions from Linux Kernel "include/linux/kernel.h"
 *****************************************************************************/
#define _RET_IP_		(unsigned long)__builtin_return_address(0)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

/******************************************************************************
 * KASAN definitions from Linux Kernel "include/linux/kasan.h"
 *****************************************************************************/
#define KASAN_SHADOW_SCALE_SHIFT 3

static inline void *kasan_mem_to_shadow(const void *addr)
{
	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
		+ KASAN_SHADOW_OFFSET;
}

/******************************************************************************
 * KASAN definitions from Linux Kernel "mm/kasan/kasan.h"
 *****************************************************************************/
#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */

/*
 * Stack redzone shadow values
 * (Those are compiler's ABI, don't change them)
 */
#define KASAN_STACK_LEFT        0xF1
#define KASAN_STACK_MID         0xF2
#define KASAN_STACK_RIGHT       0xF3
#define KASAN_STACK_PARTIAL     0xF4

/* Don't break randconfig/all*config builds */
#ifndef KASAN_ABI_VERSION
#define KASAN_ABI_VERSION 1
#endif

struct kasan_access_info {
	const void *access_addr;
	const void *first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

/* The layout of struct dictated by compiler */
struct kasan_source_location {
	const char *filename;
	int line_no;
	int column_no;
};

/* The layout of struct dictated by compiler */
struct kasan_global {
	const void *beg;		/* Address of the beginning of the global variable. */
	size_t size;			/* Size of the global variable. */
	size_t size_with_redzone;	/* Size of the variable + size of the red zone. 32 bytes aligned */
	const void *name;
	const void *module_name;	/* Name of the module where the global variable is declared. */
	unsigned long has_dynamic_init;	/* This needed for C++ */
	struct kasan_source_location *location;
};

static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
{
	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
		<< KASAN_SHADOW_SCALE_SHIFT);
}

/******************************************************************************
 * KASAN implementation from Linux Kernel "mm/kasan/kasan.c"
 *****************************************************************************/
static inline void kasan_poison_shadow(const void *address, size_t size, u8 value)
{
	void *shadow_start, *shadow_end;

	shadow_start = kasan_mem_to_shadow(address);
	shadow_end = kasan_mem_to_shadow(address + size);

	memset(shadow_start, value, shadow_end - shadow_start);
}

static inline void kasan_unpoison_shadow(const void *address, size_t size)
{
	kasan_poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

static inline unsigned long bytes_is_zero(const u8 *start,
					size_t size)
{
	while (size) {
		if (unlikely(*start))
			return (unsigned long)start;
		start++;
		size--;
	}

	return 0;
}

static inline unsigned long memory_is_zero(const void *start,
						const void *end)
{
	unsigned int words;
	unsigned long ret;
	unsigned int prefix = (unsigned long)start % 8;

	if (end - start <= 16)
		return bytes_is_zero(start, end - start);

	if (prefix) {
		prefix = 8 - prefix;
		ret = bytes_is_zero(start, prefix);
		if (unlikely(ret))
			return ret;
		start += prefix;
	}

	words = (end - start) / 8;
	while (words) {
		if (unlikely(*(u64 *)start))
			return bytes_is_zero(start, 8);
		start += 8;
		words--;
	}

	return bytes_is_zero(start, (end - start) % 8);
}

/*
 * All functions below always inlined so compiler could
 * perform better optimizations in each of __asan_loadX/__assn_storeX
 * depending on memory access size X.
 */

static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_2(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 1))
			return true;

		/*
		 * If single shadow byte covers 2-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		if (likely(((addr + 1) & KASAN_SHADOW_MASK) != 0))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_4(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 3))
			return true;

		/*
		 * If single shadow byte covers 4-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		if (likely(((addr + 3) & KASAN_SHADOW_MASK) >= 3))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_8(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 7))
			return true;

		/*
		 * If single shadow byte covers 8-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		//if (likely(IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
	//		return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static inline bool memory_is_poisoned_n(unsigned long addr,
						size_t size)
{
	unsigned long ret;

	ret = memory_is_zero(kasan_mem_to_shadow((void *)addr),
			kasan_mem_to_shadow((void *)addr + size - 1) + 1);

	if (unlikely(ret)) {
		unsigned long last_byte = addr + size - 1;
		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);

		if (unlikely(ret != (unsigned long)last_shadow ||
			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
			return true;
	}
	return false;
}

static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
{
	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			return memory_is_poisoned_1(addr);
		case 2:
			return memory_is_poisoned_2(addr);
		case 4:
			return memory_is_poisoned_4(addr);
		case 8:
			return memory_is_poisoned_8(addr);
		}
	}

	return memory_is_poisoned_n(addr, size);
}

static inline void check_memory_region(unsigned long addr,
						size_t size, bool write)
{
	if (unlikely(size == 0))
		return;

	if (unlikely((void *)addr < (void*)0xc0000000)) {
		kasan_report(addr, size, write, _RET_IP_);
		return;
	}

	if (likely(!memory_is_poisoned(addr, size)))
		return;

	kasan_report(addr, size, write, _RET_IP_);
}

/******************************************************************************
 * LK-specific KASAN hooks
 *****************************************************************************/
void _kasan_hook_malloc(void *ptr, size_t size, void *redzone, size_t redsize)
{
	kasan_unpoison_shadow(ptr, size);
	if ((NULL != redzone) && (0 != redsize))
	{
		kasan_poison_shadow(redzone, redsize, KASAN_KMALLOC_REDZONE);
	}
}

void _kasan_hook_free(void *ptr, size_t size)
{
	//TODO(astarasikov): implement it correctly in the heap
	kasan_poison_shadow(ptr, size, KASAN_KMALLOC_REDZONE);
}

/******************************************************************************
 * LK-specific KASAN implementation
 *****************************************************************************/
int __asan_option_detect_stack_use_after_return;

void __asan_handle_no_return(void) {
}

void __asan_init_v4(void)
{
	printf("%s\n", __func__);
}

#define EXPR_OR(_expr, _or) ((_expr) ? (_expr) : (_or))

static void _kasan_init_poison(void)
{
	static int once = 0;
	if (once) {
		//TODO(astarasikov): define global KASAN_SHADOW_SIZE symbol
		memset((void*)KASAN_SHADOW_OFFSET, KASAN_FREE_PAGE, 0x02000000);
		return;
	}
	once = 1;
}

void register_global(struct kasan_global *global)
{
	if (LK_DEBUG_KASAN_GLOBALS) {
		printf("%s: global=%p size=%x(%x) name=<%s> file=<%s> line=%d\n",
			__func__, global,
			global->size, global->size_with_redzone,
			(const char*)EXPR_OR(global->name, "XXX"),
			(const char*)(global->location ? (global->location->filename ? global->location->filename : "FILE?") : "MOD?"),
			global->location ? global->location->line_no : -1);
	}

	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
	kasan_unpoison_shadow(global->beg, global->size);
	kasan_poison_shadow(global->beg + aligned_size,
		global->size_with_redzone - aligned_size,
		KASAN_GLOBAL_REDZONE);
}

void __asan_register_globals(struct kasan_global *globals, size_t size)
{
	_kasan_init_poison();
	size_t i;
	if (LK_DEBUG_KASAN_GLOBALS) {
		printf("%s: globals=%p size=%x abi=%d\n", __func__, globals, size, KASAN_ABI_VERSION);
	}
	for (i = 0; i < size; i++) {
		register_global(globals + i);
	}
}

void __asan_unregister_globals(struct kasan_global *globals, size_t size)
{
	if (LK_DEBUG_KASAN_GLOBALS) {
		printf("%s: globals=%p size=%x\n", __func__, globals, size);
	}
}

#define ASAN_LOAD_STORE_DUMMY(size) \
	void __asan_load##size##_noabort(unsigned long addr) { \
		check_memory_region(addr, size, false); \
	}\
	void __asan_store##size##_noabort(unsigned long addr) { \
		check_memory_region(addr, size, true); \
	}

ASAN_LOAD_STORE_DUMMY(1);
ASAN_LOAD_STORE_DUMMY(2);
ASAN_LOAD_STORE_DUMMY(4);
ASAN_LOAD_STORE_DUMMY(8);

void __asan_loadN_noabort(unsigned long addr, size_t size) {
	check_memory_region(addr, size, false);
}

void __asan_storeN_noabort(unsigned long addr, size_t size) {
	check_memory_region(addr, size, true);
}
