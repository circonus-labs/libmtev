/* plock - progressive locks
 *
 * Copyright (C) 2012-2017 Willy Tarreau <w@1wt.eu>
 * Copyright (C) 2018 Circonus, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MTEV_PLOCK_H
#define MTEV_PLOCK_H

#include <mtev_defines.h>
#include <pthread.h>
#include <errno.h>

typedef enum {
  MTEV_PLOCK_ATOMIC,
  MTEV_PLOCK_HEAVY
} mtev_plock_type_t;

typedef struct mtev_plock {
  mtev_plock_type_t type;
  union {
    struct {
      pthread_rwlock_t rwlock;
      pthread_mutex_t  slock;
    } heavy;
    unsigned long atomic;
  } impl;
} mtev_plock_t;

#ifdef __cplusplus
#define ASM asm
#else
#define ASM __asm
#endif

/* compiler-only memory barrier, for use around locks */
#define pl_barrier() do {			\
		ASM volatile("" ::: "memory");	\
	} while (0)

#if defined(__i386__) || defined (__i486__) || defined (__i586__) || defined (__i686__) || defined (__x86_64__)

/* full memory barrier using mfence when SSE2 is supported, falling back to
 * "lock add %esp" (gcc uses "lock add" or "lock or").
 */
#if defined(__SSE2__)

#define pl_mb() do {                                 \
		ASM volatile("mfence" ::: "memory"); \
	} while (0)

#elif defined(__x86_64__)

#define pl_mb() do {                                                       \
		ASM volatile("lock addl $0,0 (%%rsp)" ::: "memory", "cc"); \
	} while (0)

#else /* ix86 */

#define pl_mb() do {                                                       \
		ASM volatile("lock addl $0,0 (%%esp)" ::: "memory", "cc"); \
	} while (0)

#endif /* end of pl_mb() case for sse2/x86_64/x86 */

/*
 * Generic functions common to the x86 family
 */

#define pl_cpu_relax() do {                   \
		ASM volatile("rep;nop\n");    \
	} while (0)

/* increment integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define pl_inc(ptr) (                                                         \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		ASM volatile("lock incq %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock incl %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock incw %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock incb %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_inc__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_inc__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* decrement integer value pointed to by pointer <ptr>, and return non-zero if
 * result is non-null.
 */
#define pl_dec(ptr) (                                                         \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned char ret;                                            \
		ASM volatile("lock decq %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock decl %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock decw %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock decb %0\n"                                 \
			     "setne %1\n"                                     \
			     : "+m" (*(ptr)), "=qm" (ret)                     \
			     :                                                \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_dec__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_dec__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* increment integer value pointed to by pointer <ptr>, no return */
#define pl_inc_noret(ptr) ({                                                  \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock incq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock incl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock incw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock incb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_inc_noret__(const char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_inc_noret__(__FILE__,__LINE__); \
	}                                                                     \
})

/* decrement integer value pointed to by pointer <ptr>, no return */
#define pl_dec_noret(ptr) ({                                                  \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock decq %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock decl %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock decw %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock decb %0\n"                                 \
			     : "+m" (*(ptr))                                  \
			     :                                                \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_dec_noret__(const char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_dec_noret__(__FILE__,__LINE__); \
	}                                                                     \
})

/* add integer constant <x> to integer value pointed to by pointer <ptr>,
 * no return. Size of <x> is not checked.
 */
#define pl_add(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock addq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock addl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock addw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock addb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_add__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                          \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))     \
			__unsupported_argument_size_for_pl_add__(__FILE__,__LINE__);       \
	}                                                                     \
})

/* subtract integer constant <x> from integer value pointed to by pointer
 * <ptr>, no return. Size of <x> is not checked.
 */
#define pl_sub(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock subq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock subl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock subw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock subb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_sub__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_sub__(__FILE__,__LINE__);   \
	}                                                                     \
})

/* binary and integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_and(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock andq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock andl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock andw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock andb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_and__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_and__(__FILE__,__LINE__);    \
	}                                                                     \
})

/* binary or integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_or(ptr, x) ({                                                      \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock orq %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock orl %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock orw %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock orb %1, %0\n"                              \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_or__(const char *,int);     \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_or__(__FILE__,__LINE__);     \
	}                                                                     \
})

/* binary xor integer value pointed to by pointer <ptr> with constant <x>, no
 * return. Size of <x> is not checked.
 */
#define pl_xor(ptr, x) ({                                                     \
	if (sizeof(long) == 8 && sizeof(*(ptr)) == 8) {                       \
		ASM volatile("lock xorq %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned long)(x))                      \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 4) {                                     \
		ASM volatile("lock xorl %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned int)(x))                       \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 2) {                                     \
		ASM volatile("lock xorw %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned short)(x))                     \
			     : "cc");                                         \
	} else if (sizeof(*(ptr)) == 1) {                                     \
		ASM volatile("lock xorb %1, %0\n"                             \
			     : "+m" (*(ptr))                                  \
			     : "er" ((unsigned char)(x))                      \
			     : "cc");                                         \
	} else {                                                              \
		void __unsupported_argument_size_for_pl_xor__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xor__(__FILE__,__LINE__);            \
	}                                                                     \
})

/* test and set bit <bit> in integer value pointed to by pointer <ptr>. Returns
 * 0 if the bit was not set, or ~0 of the same type as *ptr if it was set. Note
 * that there is no 8-bit equivalent operation.
 */
#define pl_bts(ptr, bit) (                                                    \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		ASM volatile("lock btsq %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned long)(bit))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		ASM volatile("lock btsl %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned int)(bit))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		ASM volatile("lock btsw %2, %0\n\t"                           \
			     "sbb %1, %1\n\t"                                 \
			     : "+m" (*(ptr)), "=r" (ret)                      \
			     : "Ir" ((unsigned short)(bit))                   \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_bts__(const char *,int);    \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
			__unsupported_argument_size_for_pl_bts__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* Note: for an unclear reason, gcc's __sync_fetch_and_add() implementation
 * produces less optimal than hand-crafted ASM code so let's implement here the
 * operations we need for the most common archs.
 */

/* fetch-and-add: fetch integer value pointed to by pointer <ptr>, add <x> to
 * to <*ptr> and return the previous value.
 */
#define pl_xadd(ptr, x) (                                                     \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		ASM volatile("lock xaddq %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		ASM volatile("lock xaddl %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		ASM volatile("lock xaddw %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		ASM volatile("lock xaddb %0, %1\n"                            \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xadd__(const char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
			__unsupported_argument_size_for_pl_xadd__(__FILE__,__LINE__);   \
		0;                                                            \
	})                                                                    \
)

/* exchage value <x> with integer value pointed to by pointer <ptr>, and return
 * previous <*ptr> value. <x> must be of the same size as <*ptr>.
 */
#define pl_xchg(ptr, x) (                                                     \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret = (unsigned long)(x);                       \
		ASM volatile("xchgq %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret = (unsigned int)(x);                         \
		ASM volatile("xchgl %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret = (unsigned short)(x);                     \
		ASM volatile("xchgw %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret = (unsigned char)(x);                       \
		ASM volatile("xchgb %0, %1\n"                                 \
			     :  "=r" (ret), "+m" (*(ptr))                     \
			     : "0" (ret)                                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_xchg__(const char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                       \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8))  \
		__unsupported_argument_size_for_pl_xchg__(__FILE__,__LINE__);           \
		0;                                                            \
	})                                                                    \
)

/* compare integer value <*ptr> with <old> and exchange it with <new> if
 * it matches, and return <old>. <old> and <new> must be of the same size as
 * <*ptr>.
 */
#define pl_cmpxchg(ptr, old, new) (                                           \
	(sizeof(long) == 8 && sizeof(*(ptr)) == 8) ? ({                       \
		unsigned long ret;                                            \
		ASM volatile("lock cmpxchgq %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned long)(new)),                    \
			       "0" ((unsigned long)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 4) ? ({                                       \
		unsigned int ret;                                             \
		ASM volatile("lock cmpxchgl %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned int)(new)),                     \
			       "0" ((unsigned int)(old))                      \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 2) ? ({                                       \
		unsigned short ret;                                           \
		ASM volatile("lock cmpxchgw %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned short)(new)),                   \
			       "0" ((unsigned short)(old))                    \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : (sizeof(*(ptr)) == 1) ? ({                                       \
		unsigned char ret;                                            \
		ASM volatile("lock cmpxchgb %2,%1"                            \
			     : "=a" (ret), "+m" (*(ptr))                      \
			     : "r" ((unsigned char)(new)),                    \
			       "0" ((unsigned char)(old))                     \
			     : "cc");                                         \
		ret; /* return value */                                       \
	}) : ({                                                               \
		void __unsupported_argument_size_for_pl_cmpxchg__(const char *,int);   \
		if (sizeof(*(ptr)) != 1 && sizeof(*(ptr)) != 2 &&                      \
		    sizeof(*(ptr)) != 4 && (sizeof(long) != 8 || sizeof(*(ptr)) != 8)) \
		__unsupported_argument_size_for_pl_cmpxchg__(__FILE__,__LINE__);       \
		0;                                                            \
	})                                                                    \
)

#else
/* generic implementations */

#define pl_cpu_relax() do {             \
		ASM volatile("");       \
	} while (0)

/* full memory barrier */
#define pl_mb() do {                    \
		__sync_synchronize();   \
	} while (0)

#define pl_inc_noret(ptr)     ({ __sync_add_and_fetch((ptr), 1);   })
#define pl_dec_noret(ptr)     ({ __sync_sub_and_fetch((ptr), 1);   })
#define pl_inc(ptr)           ({ __sync_add_and_fetch((ptr), 1);   })
#define pl_dec(ptr)           ({ __sync_sub_and_fetch((ptr), 1);   })
#define pl_add(ptr, x)        ({ __sync_add_and_fetch((ptr), (x)); })
#define pl_and(ptr, x)        ({ __sync_and_and_fetch((ptr), (x)); })
#define pl_or(ptr, x)         ({ __sync_or_and_fetch((ptr), (x));  })
#define pl_xor(ptr, x)        ({ __sync_xor_and_fetch((ptr), (x)); })
#define pl_sub(ptr, x)        ({ __sync_sub_and_fetch((ptr), (x)); })
#define pl_bts(ptr, bit)      ({ typeof(*(ptr)) __pl_t = (1u << (bit));         \
                                 __sync_fetch_and_or((ptr), __pl_t) & __pl_t;	\
                              })
#define pl_xadd(ptr, x)       ({ __sync_fetch_and_add((ptr), (x)); })
#define pl_cmpxchg(ptr, o, n) ({ __sync_val_compare_and_swap((ptr), (o), (n)); })
#define pl_xchg(ptr, x)       ({ typeof(*(ptr)) __pl_t;                                       \
                                 do { __pl_t = *(ptr);                                        \
                                 } while (!__sync_bool_compare_and_swap((ptr), __pl_t, (x))); \
                                 __pl_t;                                                      \
                              })

#endif

/* 64 bit */
#define PLOCK64_RL_1   0x0000000000000004ULL
#define PLOCK64_RL_ANY 0x00000000FFFFFFFCULL
#define PLOCK64_SL_1   0x0000000100000000ULL
#define PLOCK64_SL_ANY 0x0000000300000000ULL
#define PLOCK64_WL_1   0x0000000400000000ULL
#define PLOCK64_WL_ANY 0xFFFFFFFC00000000ULL

/* 32 bit */
#define PLOCK32_RL_1   0x00000004
#define PLOCK32_RL_ANY 0x0000FFFC
#define PLOCK32_SL_1   0x00010000
#define PLOCK32_SL_ANY 0x00030000
#define PLOCK32_WL_1   0x00040000
#define PLOCK32_WL_ANY 0xFFFC0000

#if __cplusplus
#define __REGISTER
#else
#define __REGISTER                             register
#endif

/* dereferences <*p> as unsigned long without causing aliasing issues */
#define pl_deref_long(p) ({ volatile unsigned long *__pl_l = (unsigned long *)(p); *__pl_l; })

/* dereferences <*p> as unsigned int without causing aliasing issues */
#define pl_deref_int(p) ({ volatile unsigned int *__pl_i = (unsigned int *)(p); *__pl_i; })

/* This function waits for <lock> to release all bits covered by <mask>, and
 * enforces an exponential backoff using CPU pauses to limit the pollution to
 * the other threads' caches. The progression follows (2^N)-1, limited to 255
 * iterations, which is way sufficient even for very large numbers of threads.
 * The function slightly benefits from size optimization under gcc, but Clang
 * cannot do it, so it's not done here, as it doesn't make a big difference.
 */
__attribute__((unused,noinline))
static void pl_wait_unlock_long(const unsigned long *lock, const unsigned long mask)
{
	unsigned char m = 0;

	do {
		unsigned char loops = m + 1;
		m = (m << 1) + 1;
		do {
			pl_cpu_relax();
		} while (--loops);
	} while (__builtin_expect(pl_deref_long(lock) & mask, 0));
}

/* This function waits for <lock> to release all bits covered by <mask>, and
 * enforces an exponential backoff using CPU pauses to limit the pollution to
 * the other threads' caches. The progression follows (2^N)-1, limited to 255
 * iterations, which is way sufficient even for very large numbers of threads.
 * The function slightly benefits from size optimization under gcc, but Clang
 * cannot do it, so it's not done here, as it doesn't make a big difference.
 */
__attribute__((unused,noinline))
static void pl_wait_unlock_int(const unsigned int *lock, const unsigned int mask)
{
	unsigned char m = 0;

	do {
		unsigned char loops = m + 1;
		m = (m << 1) + 1;
		do {
			pl_cpu_relax();
		} while (--loops);
	} while (__builtin_expect(pl_deref_int(lock) & mask, 0));
}

/* request shared read access (R), return non-zero on success, otherwise 0 */
#define pl_try_r(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_WL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_RL_1) & PLOCK64_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_WL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_RL_1) & PLOCK32_WL_ANY;               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_RL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_r__(const char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_r__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request shared read access (R) and wait for it. In order not to disturb a W
 * lock waiting for all readers to leave, we first check if a W lock is held
 * before trying to claim the R lock.
 */
#define pl_take_r(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__REGISTER unsigned long *__lk_r = (unsigned long *)(lock);                               \
		__REGISTER unsigned long __set_r = PLOCK64_RL_1;                                 \
		__REGISTER unsigned long __msk_r = PLOCK64_WL_ANY;                               \
		while (1) {                                                                    \
			if (__builtin_expect(pl_deref_long(__lk_r) & __msk_r, 0))              \
				pl_wait_unlock_long(__lk_r, __msk_r);                          \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__REGISTER unsigned int *__lk_r = (unsigned int *)(lock);                                \
		__REGISTER unsigned int __set_r = PLOCK32_RL_1;                                  \
		__REGISTER unsigned int __msk_r = PLOCK32_WL_ANY;                                \
		while (1) {                                                                    \
			if (__builtin_expect(pl_deref_int(__lk_r) & __msk_r, 0))               \
				pl_wait_unlock_int(__lk_r, __msk_r);                           \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_r__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_r__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release the read access (R) lock */
#define pl_drop_r(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_RL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_RL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_r__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_r__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* request a seek access (S), return non-zero on success, otherwise 0 */
#define pl_try_s(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1 | PLOCK64_RL_1) &                \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1 | PLOCK64_RL_1);                   \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_SL_1 | PLOCK32_RL_1) &                \
			      (PLOCK32_WL_ANY | PLOCK32_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_SL_1 | PLOCK32_RL_1);                   \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_s__(const char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_s__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request a seek access (S) and wait for it. The lock is immediately claimed,
 * and only upon failure an exponential backoff is used. S locks rarely compete
 * with W locks so S will generally not disturb W. As the S lock may be used as
 * a spinlock, it's important to grab it as fast as possible.
 */
#define pl_take_s(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__REGISTER unsigned long *__lk_r = (unsigned long *)(lock);                               \
		__REGISTER unsigned long __set_r = PLOCK64_SL_1 | PLOCK64_RL_1;                  \
		__REGISTER unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		while (1) {                                                                    \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_long(__lk_r, __msk_r);                                  \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__REGISTER unsigned int *__lk_r = (unsigned int *)(lock);                                \
		__REGISTER unsigned int __set_r = PLOCK32_SL_1 | PLOCK32_RL_1;                   \
		__REGISTER unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		while (1) {                                                                    \
			if (!__builtin_expect(pl_xadd(__lk_r, __set_r) & __msk_r, 0))          \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_int(__lk_r, __msk_r);                                   \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_s__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_s__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release the seek access (S) lock */
#define pl_drop_s(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_SL_1 + PLOCK64_RL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_SL_1 + PLOCK32_RL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_s__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_s__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* drop the S lock and go back to the R lock */
#define pl_stor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_SL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_SL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stor__(const char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_stor__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* take the W lock under the S lock */
#define pl_stow(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_xadd((lock), PLOCK64_WL_1);                          \
		while ((__pl_r & PLOCK64_RL_ANY) != PLOCK64_RL_1)                              \
			__pl_r = pl_deref_long(lock);                                          \
		pl_barrier();                                                                  \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_xadd((lock), PLOCK32_WL_1);                           \
		while ((__pl_r & PLOCK32_RL_ANY) != PLOCK32_RL_1)                              \
			__pl_r = pl_deref_int(lock);                                           \
		pl_barrier();                                                                  \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_stow__(const char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_stow__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* drop the W lock and go back to the S lock */
#define pl_wtos(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtos__(const char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_wtos__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* drop the W lock and go back to the R lock */
#define pl_wtor(lock) (                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1);                                     \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1);                                     \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_wtor__(const char *,int);                    \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_wtor__(__FILE__,__LINE__);          \
	})                                                                                     \
)

/* request a write access (W), return non-zero on success, otherwise 0.
 *
 * Below there is something important : by taking both W and S, we will cause
 * an overflow of W at 4/5 of the maximum value that can be stored into W due
 * to the fact that S is 2 bits, so we're effectively adding 5 to the word
 * composed by W:S. But for all words multiple of 4 bits, the maximum value is
 * multiple of 15 thus of 5. So the largest value we can store with all bits
 * set to one will be met by adding 5, and then adding 5 again will place value
 * 1 in W and value 0 in S, so we never leave W with 0. Also, even upon such an
 * overflow, there's no risk to confuse it with an atomic lock because R is not
 * null since it will not have overflown. For 32-bit locks, this situation
 * happens when exactly 13108 threads try to grab the lock at once, W=1, S=0
 * and R=13108. For 64-bit locks, it happens at 858993460 concurrent writers
 * where W=1, S=0 and R=858993460.
 */
#define pl_try_w(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);  \
			if (__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) { \
				/* a writer, seeker or atomic is present, let's leave */       \
				pl_sub((lock), PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);    \
				__pl_r &= (PLOCK64_WL_ANY | PLOCK64_SL_ANY); /* return value */\
			} else {                                                               \
				/* wait for all other readers to leave */                      \
				while (__pl_r)                                                 \
					__pl_r = pl_deref_long(lock) -                         \
						(PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);  \
			if (__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) { \
				/* a writer, seeker or atomic is present, let's leave */       \
				pl_sub((lock), PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);    \
				__pl_r &= (PLOCK32_WL_ANY | PLOCK32_SL_ANY); /* return value */\
			} else {                                                               \
				/* wait for all other readers to leave */                      \
				while (__pl_r)                                                 \
					__pl_r = pl_deref_int(lock) -                          \
						(PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_w__(const char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_w__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request a write access (W) and wait for it. The lock is immediately claimed,
 * and only upon failure an exponential backoff is used.
 */
#define pl_take_w(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__REGISTER unsigned long *__lk_r = (unsigned long *)(lock);                               \
		__REGISTER unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1;   \
		__REGISTER unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		__REGISTER unsigned long __pl_r;                                                 \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (!__builtin_expect(__pl_r & __msk_r, 0))                            \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_long(__lk_r, __msk_r);                                  \
		}                                                                              \
		/* wait for all other readers to leave */                                      \
		while (__builtin_expect(__pl_r, 0))                                            \
			__pl_r = pl_deref_long(__lk_r) - __set_r;                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__REGISTER unsigned int *__lk_r = (unsigned int *)(lock);                                \
		__REGISTER unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1;    \
		__REGISTER unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		__REGISTER unsigned int __pl_r;                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (!__builtin_expect(__pl_r & __msk_r, 0))                            \
				break;                                                         \
			pl_sub(__lk_r, __set_r);                                               \
			pl_wait_unlock_int(__lk_r, __msk_r);                                   \
		}                                                                              \
		/* wait for all other readers to leave */                                      \
		while (__builtin_expect(__pl_r, 0))                                            \
			__pl_r = pl_deref_int(__lk_r) - __set_r;                               \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_w__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_w__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* drop the write (W) lock entirely */
#define pl_drop_w(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1 | PLOCK64_SL_1 | PLOCK64_RL_1);                      \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1 | PLOCK32_SL_1 | PLOCK32_RL_1);                      \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_w__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_w__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* Try to upgrade from R to S, return non-zero on success, otherwise 0.
 * This lock will fail if S or W are already held. In case of failure to grab
 * the lock, it MUST NOT be retried without first dropping R, or it may never
 * complete due to S waiting for R to leave before upgrading to W.
 */
#define pl_try_rtos(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock);                                    \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK64_WL_ANY | PLOCK64_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK64_SL_1) &                               \
			      (PLOCK64_WL_ANY | PLOCK64_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK64_SL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock);                                      \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r & (PLOCK32_WL_ANY | PLOCK32_SL_ANY), 0)) {        \
			__pl_r = pl_xadd((lock), PLOCK32_SL_1) &                               \
			      (PLOCK32_WL_ANY | PLOCK32_SL_ANY);                               \
			if (__builtin_expect(__pl_r, 0))                                       \
				pl_sub((lock), PLOCK32_SL_1);                                  \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtos__(const char *,int);                \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtos__(__FILE__,__LINE__);      \
		0;                                                                             \
	})                                                                                     \
)


/* Try to upgrade from R to W, return non-zero on success, otherwise 0.
 * This lock will fail if S or W are already held. In case of failure to grab
 * the lock, it MUST NOT be retried without first dropping R, or it may never
 * complete due to S waiting for R to leave before upgrading to W. It waits for
 * the last readers to leave.
 */
#define pl_try_rtow(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__REGISTER unsigned long *__lk_r = (unsigned long *)(lock);                               \
		__REGISTER unsigned long __set_r = PLOCK64_WL_1 | PLOCK64_SL_1;                  \
		__REGISTER unsigned long __msk_r = PLOCK64_WL_ANY | PLOCK64_SL_ANY;              \
		__REGISTER unsigned long __pl_r;                                                 \
		pl_barrier();                                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				if (pl_xadd(__lk_r, - __set_r))                                \
					break; /* the caller needs to drop the lock now */     \
				continue;  /* lock was released, try again */                  \
			}                                                                      \
			/* ok we're the only writer, wait for readers to leave */              \
			while (__builtin_expect(__pl_r, 0))                                    \
				__pl_r = pl_deref_long(__lk_r) - (PLOCK64_WL_1|PLOCK64_SL_1|PLOCK64_RL_1); \
			/* now return with __pl_r = 0 */                                       \
			break;                                                                 \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__REGISTER unsigned int *__lk_r = (unsigned int *)(lock);                                \
		__REGISTER unsigned int __set_r = PLOCK32_WL_1 | PLOCK32_SL_1;                   \
		__REGISTER unsigned int __msk_r = PLOCK32_WL_ANY | PLOCK32_SL_ANY;               \
		__REGISTER unsigned int __pl_r;                                                  \
		pl_barrier();                                                                  \
		while (1) {                                                                    \
			__pl_r = pl_xadd(__lk_r, __set_r);                                     \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				if (pl_xadd(__lk_r, - __set_r))                                \
					break; /* the caller needs to drop the lock now */     \
				continue;  /* lock was released, try again */                  \
			}                                                                      \
			/* ok we're the only writer, wait for readers to leave */              \
			while (__builtin_expect(__pl_r, 0))                                    \
				__pl_r = pl_deref_int(__lk_r) - (PLOCK32_WL_1|PLOCK32_SL_1|PLOCK32_RL_1); \
			/* now return with __pl_r = 0 */                                       \
			break;                                                                 \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtow__(const char *,int);                \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtow__(__FILE__,__LINE__);      \
		0;                                                                             \
	})                                                                                     \
)


/* request atomic write access (A), return non-zero on success, otherwise 0.
 * It's a bit tricky as we only use the W bits for this and want to distinguish
 * between other atomic users and regular lock users. We have to give up if an
 * S lock appears. It's possible that such a lock stays hidden in the W bits
 * after an overflow, but in this case R is still held, ensuring we stay in the
 * loop until we discover the conflict. The lock only return successfully if all
 * readers are gone (or converted to A).
 */
#define pl_try_a(lock) (                                                                       \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1);                                \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK64_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK64_WL_1);                          \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK64_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_long(lock);                                  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1);                                \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK32_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK32_WL_1);                          \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK32_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_int(lock);                                   \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_a__(const char *,int);                   \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_a__(__FILE__,__LINE__);         \
		0;                                                                             \
	})                                                                                     \
)

/* request atomic write access (A) and wait for it. See comments in pl_try_a() for
 * explanations.
 */
#define pl_take_a(lock)                                                                        \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		__REGISTER unsigned long *__lk_r = (unsigned long *)(lock);                               \
		__REGISTER unsigned long __set_r = PLOCK64_WL_1;                                 \
		__REGISTER unsigned long __msk_r = PLOCK64_SL_ANY;                               \
		__REGISTER unsigned long __pl_r;                                                 \
		__pl_r = pl_xadd(__lk_r, __set_r);                                             \
		while (__builtin_expect(__pl_r & PLOCK64_RL_ANY, 0)) {                         \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				pl_sub(__lk_r, __set_r);                                       \
				pl_wait_unlock_long(__lk_r, __msk_r);                          \
				__pl_r = pl_xadd(__lk_r, __set_r);                             \
				continue;                                                      \
			}                                                                      \
			/* wait for all readers to leave or upgrade */                         \
			pl_cpu_relax(); pl_cpu_relax(); pl_cpu_relax();                        \
			__pl_r = pl_deref_long(lock);                                          \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		__REGISTER unsigned int *__lk_r = (unsigned int *)(lock);                                \
		__REGISTER unsigned int __set_r = PLOCK32_WL_1;                                  \
		__REGISTER unsigned int __msk_r = PLOCK32_SL_ANY;                                \
		__REGISTER unsigned int __pl_r;                                     \
		__pl_r = pl_xadd(__lk_r, __set_r);                                             \
		while (__builtin_expect(__pl_r & PLOCK32_RL_ANY, 0)) {                         \
			if (__builtin_expect(__pl_r & __msk_r, 0)) {                           \
				pl_sub(__lk_r, __set_r);                                       \
				pl_wait_unlock_int(__lk_r, __msk_r);                           \
				__pl_r = pl_xadd(__lk_r, __set_r);                             \
				continue;                                                      \
			}                                                                      \
			/* wait for all readers to leave or upgrade */                         \
			pl_cpu_relax(); pl_cpu_relax(); pl_cpu_relax();                        \
			__pl_r = pl_deref_int(lock);                                           \
		}                                                                              \
		pl_barrier();                                                                  \
		0;                                                                             \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_take_a__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_take_a__(__FILE__,__LINE__);        \
		0;                                                                             \
	})

/* release atomic write access (A) lock */
#define pl_drop_a(lock) (                                                                      \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK64_WL_1);                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		pl_barrier();                                                                  \
		pl_sub(lock, PLOCK32_WL_1);                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_drop_a__(const char *,int);                  \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_drop_a__(__FILE__,__LINE__);        \
	})                                                                                     \
)

/* Try to upgrade from R to A, return non-zero on success, otherwise 0.
 * This lock will fail if S is held or appears while waiting (typically due to
 * a previous grab that was disguised as a W due to an overflow). In case of
 * failure to grab the lock, it MUST NOT be retried without first dropping R,
 * or it may never complete due to S waiting for R to leave before upgrading
 * to W. The lock succeeds once there's no more R (ie all of them have either
 * completed or were turned to A).
 */
#define pl_try_rtoa(lock) (                                                                    \
	(sizeof(long) == 8 && sizeof(*(lock)) == 8) ? ({                                       \
		unsigned long __pl_r = pl_deref_long(lock) & PLOCK64_SL_ANY;                   \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK64_WL_1 - PLOCK64_RL_1);                 \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK64_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK64_WL_1 - PLOCK64_RL_1);           \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK64_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_long(lock);                                  \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : (sizeof(*(lock)) == 4) ? ({                                                       \
		unsigned int __pl_r = pl_deref_int(lock) & PLOCK32_SL_ANY;                     \
		pl_barrier();                                                                  \
		if (!__builtin_expect(__pl_r, 0)) {                                            \
			__pl_r = pl_xadd((lock), PLOCK32_WL_1 - PLOCK32_RL_1);                 \
			while (1) {                                                            \
				if (__builtin_expect(__pl_r & PLOCK32_SL_ANY, 0)) {            \
					pl_sub((lock), PLOCK32_WL_1 - PLOCK32_RL_1);           \
					break;  /* return !__pl_r */                           \
				}                                                              \
				__pl_r &= PLOCK32_RL_ANY;                                      \
				if (!__builtin_expect(__pl_r, 0))                              \
					break;  /* return !__pl_r */                           \
				__pl_r = pl_deref_int(lock);                                   \
			}                                                                      \
		}                                                                              \
		!__pl_r; /* return value */                                                    \
	}) : ({                                                                                \
		void __unsupported_argument_size_for_pl_try_rtoa__(const char *,int);                \
		if (sizeof(*(lock)) != 4 && (sizeof(long) != 8 || sizeof(*(lock)) != 8))       \
			__unsupported_argument_size_for_pl_try_rtoa__(__FILE__,__LINE__);      \
		0;                                                                             \
	})                                                                                     \
)

static inline void
mtev_plock_init(mtev_plock_t *lock, mtev_plock_type_t type) {
  memset(lock, 0, sizeof(*lock));
  lock->type = type;
  if(lock->type == MTEV_PLOCK_HEAVY) {
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
#ifdef HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NP);
#endif
    pthread_rwlock_init(&lock->impl.heavy.rwlock, &attr);
    pthread_rwlockattr_destroy(&attr);
    pthread_mutex_init(&lock->impl.heavy.slock, NULL);
  }
}

static inline void
mtev_plock_destroy(mtev_plock_t *lock) {
  if(lock->type == MTEV_PLOCK_HEAVY) {
    pthread_mutex_destroy(&lock->impl.heavy.slock);
    pthread_rwlock_destroy(&lock->impl.heavy.rwlock);
  }
}

static inline void
mtev_plock_heavy_take_r(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_rwlock_rdlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
}

#define mtev_plock_take_r(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_take_r(lock); else pl_take_r(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_drop_r(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_rwlock_unlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
}

#define mtev_plock_drop_r(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_drop_r(lock); else pl_drop_r(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_take_s(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_mutex_lock(&lock->impl.heavy.slock);
  assert(rv == 0);
}

#define mtev_plock_take_s(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_take_s(lock); else pl_take_s(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_drop_s(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_mutex_unlock(&lock->impl.heavy.slock);
  assert(rv == 0);
}

#define mtev_plock_drop_s(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_drop_s(lock); else pl_drop_s(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_take_w(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_mutex_lock(&lock->impl.heavy.slock);
  assert(rv == 0);
  rv = pthread_rwlock_wrlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
}

#define mtev_plock_take_w(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_take_w(lock); else pl_take_w(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_drop_w(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_rwlock_unlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
  rv = pthread_mutex_unlock(&lock->impl.heavy.slock);
  assert(rv == 0);
}

#define mtev_plock_drop_w(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_drop_w(lock); else pl_drop_w(&((lock)->impl.atomic)); \
} while(0)

static inline mtev_boolean
mtev_plock_heavy_try_rtos(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_mutex_trylock(&lock->impl.heavy.slock);
  if(rv < 0) {
    assert(errno == EBUSY);
    return mtev_false;
  }
  rv = pthread_rwlock_unlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
  return mtev_true;
}

#define mtev_plock_try_rtos(lock) ( \
  ((lock)->type == MTEV_PLOCK_HEAVY) ? mtev_plock_heavy_try_rtos(lock) : \
    pl_try_rtos(&((lock)->impl.atomic)) \
)

static inline void
mtev_plock_heavy_stor(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  /* This seems like it would be priority inversion, but is not.
   * Since we always acquire the mutex before the wrlock and we
   * have the mutex, no one could be waiting for the wrlock right
   * no, so we know that our rdlock will not cause lock inversion.
   */
  int rv = pthread_rwlock_rdlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
  rv = pthread_mutex_unlock(&lock->impl.heavy.slock);
  assert(rv == 0);
}

#define mtev_plock_stor(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_stor(lock); else pl_stor(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_stow(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_rwlock_wrlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
}

#define mtev_plock_stow(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_stow(lock); else pl_stow(&((lock)->impl.atomic)); \
} while(0)

static inline void
mtev_plock_heavy_wtos(mtev_plock_t *lock) {
  assert(lock->type == MTEV_PLOCK_HEAVY);
  int rv = pthread_rwlock_unlock(&lock->impl.heavy.rwlock);
  assert(rv == 0);
}

#define mtev_plock_wtos(lock) do { \
  if((lock)->type == MTEV_PLOCK_HEAVY) mtev_plock_heavy_wtos(lock); else pl_wtos(&((lock)->impl.atomic)); \
} while(0)

#endif
