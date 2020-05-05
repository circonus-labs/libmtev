/*
 * Copyright (c) 2020, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mtev_defines.h"
#include "mtev_logic.h"
#include "mtev_log.h"

#include <stdio.h>
#include <pcre.h>

static mtev_log_stream_t debugls;

/* Helpers for PCRE JIT... these expressions can run hot */
static uint32_t initialized = 0;
#ifdef PCRE_STUDY_JIT_COMPILE
static __thread pcre_jit_stack *tls_jit_stack;
static pthread_key_t tls_jit_stack_key;

static void
free_tls_pcre_jit_stack(void *stack) {
  pcre_jit_stack_free((pcre_jit_stack *)stack);
}
static inline pcre_jit_stack *
get_tls_pcre_jit_stack(void *arg) {
  (void)arg;
  if (tls_jit_stack == NULL) {
    tls_jit_stack = (pcre_jit_stack *)pthread_getspecific(tls_jit_stack_key);
    if (tls_jit_stack == NULL) {
      tls_jit_stack = (pcre_jit_stack *)pcre_jit_stack_alloc(1024 * 32, 512 * 1024);
      pthread_setspecific(tls_jit_stack_key, tls_jit_stack);
    }
  }
  return tls_jit_stack;
}
#endif

static void
mtev_logic_init(void) {
  if(initialized) return;
  initialized++;
  debugls = mtev_log_stream_find("debug/logic");
#ifdef PCRE_STUDY_JIT_COMPILE
  mtevAssert(pthread_key_create(&tls_jit_stack_key, free_tls_pcre_jit_stack) == 0);
#endif
}

typedef enum {
  MTEV_LOGIC_STRING,
  MTEV_LOGIC_INT64,
  MTEV_LOGIC_DOUBLE
} mtev_logic_var_type_t;

static inline const char *
mtev_logic_var_type_name(mtev_logic_var_type_t t) {
  switch(t) {
    case MTEV_LOGIC_STRING: return "s";
    case MTEV_LOGIC_INT64: return "l";
    case MTEV_LOGIC_DOUBLE: return "n";
  }
  return "?";
}

struct mtev_logic_var_t {
  mtev_logic_var_type_t type;
  struct {
    const char *s;
    int64_t     l;
    double      n;
  } value;
  size_t s_len;
  pcre *re;
  pcre_extra *re_extra;
  mtev_boolean free_s;
  char internal[40]; /* up 39 byte copies without alloc */
};

static void mtev_logic_var_clean(void *vv) {
  mtev_logic_var_t *v = vv;
  if(v->free_s) free((char *)v->value.s);
#ifdef PCRE_STUDY_JIT_COMPILE
  if(v->re_extra) pcre_free_study(v->re_extra);
#endif
  if(v->re) pcre_free(v->re);
}

static inline const char *
mtev_logic_var_tostring(mtev_logic_var_t *v, size_t *len) {
  char buff[64];
  if(v->type == MTEV_LOGIC_STRING) {
    if(len) *len = v->s_len;
    return v->value.s;
  }
  else {
    if(v->free_s) {
      free((char *)v->value.s);
      v->free_s = mtev_false;
    }
    v->value.s = NULL;
    v->s_len = 0;
    if(v->type == MTEV_LOGIC_INT64) {
      snprintf(buff, sizeof(buff), "%" PRId64, v->value.l);
      v->value.s = strdup(buff);
      v->s_len = strlen(buff);
      v->free_s = mtev_true;
    }
    else if(v->type == MTEV_LOGIC_DOUBLE) {
      snprintf(buff, sizeof(buff), "%g", v->value.n);
      v->value.s = strdup(buff);
      v->s_len = strlen(buff);
      v->free_s = mtev_true;
    }
  }
  if(len) *len = v->s_len;
  return v->value.s;
}

void
mtev_logic_var_set_stringn(mtev_logic_var_t *v, const char *s, size_t len) {
  if(v->free_s) {
    free((char *)v->value.s);
    v->free_s = mtev_false;
  }
  v->type = MTEV_LOGIC_STRING;
  v->value.s = s;
  v->s_len = len;
}

void
mtev_logic_var_set_string(mtev_logic_var_t *v, const char *s) {
  mtev_logic_var_set_stringn(v, s, s ? strlen(s) : 0);
}

void
mtev_logic_var_set_stringn_copy(mtev_logic_var_t *v, const char *s, size_t len) {
  if(v->free_s) {
    free((char *)v->value.s);
    v->free_s = mtev_false;
  }
  v->type = MTEV_LOGIC_STRING;
  if(len < sizeof(v->internal)) {
    memcpy(v->internal, s, len);
    v->internal[len] = len;
    v->value.s = v->internal;
    v->s_len = len;
  }
  else {
    v->free_s = mtev_true;
    v->value.s = strndup(s, len);
    v->s_len = len;
  }
}

void
mtev_logic_var_set_string_copy(mtev_logic_var_t *v, const char *s) {
  mtev_logic_var_set_stringn_copy(v, s, strlen(s));
}

void
mtev_logic_var_set_int64(mtev_logic_var_t *v, int64_t l) {
  if(v->free_s) {
    free((char *)v->value.s);
    v->free_s = mtev_false;
  }
  v->type = MTEV_LOGIC_INT64;
  v->value.l = l;
}

void
mtev_logic_var_set_double(mtev_logic_var_t *v, double n) {
  if(v->free_s) {
    free((char *)v->value.s);
    v->free_s = mtev_false;
  }
  v->type = MTEV_LOGIC_DOUBLE;
  v->value.n = n;
}

typedef enum {
  POP_NE,
  POP_EQ,
  POP_LT,
  POP_LE,
  POP_GT,
  POP_GE,
  POP_RE,
  POP_NRE,
  POP_EXISTS
} mtev_logic_pred_op_t;

static inline const char *
mtev_logic_pred_op_name(mtev_logic_pred_op_t op) {
  switch(op) {
    case POP_NE: return "!=";
    case POP_EQ: return "=";
    case POP_LT: return "<";
    case POP_LE: return "<=";
    case POP_GT: return ">";
    case POP_GE: return ">=";
    case POP_RE: return "~";
    case POP_NRE: return "!~";
    case POP_EXISTS: return "exists";
  }
  return "unknown";
}

typedef enum {
  LOP_PREDICATE,
  LOP_AND,
  LOP_OR,
  LOP_NOT
} mtev_logic_op_t;

static inline const char *
mtev_logic_op_name(mtev_logic_op_t op) {
  switch(op) {
    case LOP_PREDICATE: return "predicate";
   case LOP_AND: return "and";
    case LOP_OR: return "or";
    case LOP_NOT: return "not";
  }
  return "unknown";
}

#define YY_LOCAL(T) static inline T
#define YYSTYPE void *
#define YY_CTX_LOCAL 1
#define YY_PARSE(X) static X
#define YY_CTX_MEMBERS \
  mtev_logic_ast_t *ast; \
  char **error; \
  const char *input_buffer; \
  size_t input_buffer_len; \
  size_t input_buffer_readidx;

#define YY_INPUT(yy, buf, result, max_size)                    \
  {                                                            \
    if (yy->input_buffer_readidx >= yy->input_buffer_len) {    \
      result = 0;                                              \
    } else {                                                   \
      *buf = yy->input_buffer[yy->input_buffer_readidx++];     \
      buf[1] = '\0';                                           \
      result = 1;                                              \
    }                                                          \
  }

typedef struct {
  mtev_logic_pred_op_t op;
  const char *left;
  mtev_logic_var_t *right;
} mtev_logic_pred_t;

typedef struct mtev_logic_node_t {
  mtev_logic_op_t logical_op;
  /* if logical_op is PREDICATE, then we use the predicate */
  mtev_logic_pred_t *predicate;
  /* otherwise there is a list */
  int nelems;
  struct mtev_logic_node_t **elems;
} mtev_logic_node_t;

static void mtev_logic_node_clean(void *vn) {
  mtev_logic_node_t *n = vn;
  free(n->predicate);
  free(n->elems);
}

struct alloc_list {
  struct alloc_list *next;
  void (*clean)(void *);
  void *obj;
};

struct mtev_logic_ast_t {
  struct alloc_list *allocations;
  struct mtev_logic_node_t *root;
};

struct mtev_logic_exec_t {
  const mtev_logic_ops_t *ops;
};

static inline void *
mtev_logic_ast_alloc(mtev_logic_ast_t *ast, size_t l, void (*clean)(void *)) {
  struct alloc_list *oc = malloc(sizeof(*oc));
  oc->clean = clean;
  oc->obj = malloc(l);
  oc->next = ast->allocations;
  ast->allocations = oc;
  return oc->obj;
}

static inline void *
mtev_logic_ast_node_predicate(mtev_logic_ast_t *ast, const char *left,
                              mtev_logic_pred_op_t op, mtev_logic_var_t *right) {
  if(op == POP_RE || op == POP_NRE) {
    const char *error;
    int erroff;
    /* compile the PCREs */
    const char *expr = mtev_logic_var_tostring(right, NULL);
    right->re = pcre_compile(expr, 0, &error, &erroff, NULL);
    if(!right->re) {
      mtevL(debugls, "logic PCRE compilation error @ %d : %s\n", erroff, error);
      return NULL;
    }
#ifdef PCRE_STUDY_JIT_COMPILE
    right->re_extra = pcre_study(right->re, PCRE_STUDY_JIT_COMPILE, &error);
    if(right->re_extra) {
      pcre_assign_jit_stack(right->re_extra, get_tls_pcre_jit_stack, NULL);
    }
#endif
  }
  mtev_logic_node_t *node = mtev_logic_ast_alloc(ast, sizeof(*node), mtev_logic_node_clean);
  memset(node, 0, sizeof(*node));
  node->logical_op = LOP_PREDICATE;
  node->predicate = calloc(1, sizeof(*node->predicate));
  node->predicate->left = left;
  node->predicate->op = op;
  node->predicate->right = right;
  return node;
}

static inline void *
mtev_logic_ast_node_op(mtev_logic_ast_t *ast, mtev_logic_node_t *existing, mtev_logic_node_t *arg) {
  if(existing == NULL) {
    existing = mtev_logic_ast_alloc(ast, sizeof(*existing), mtev_logic_node_clean);
    memset(existing, 0, sizeof(*existing));
    existing->elems = malloc(sizeof(*existing->elems));
  }
  else {
    existing->elems = realloc(existing->elems, (existing->nelems + 1) * sizeof(*existing->elems));
  }
  existing->elems[existing->nelems] = arg;
  existing->nelems++;
  return existing;
}

static inline bool
mtev_logic_ast_node_set_op(mtev_logic_ast_t *ast, mtev_logic_node_t *node, mtev_logic_op_t op) {
  (void)ast;
  if(node == NULL) return false;
  if(node->nelems < 1) return false;
  if(op == LOP_NOT && node->nelems != 1) return false;
  node->logical_op = op;
  return true;
}
static inline void *
mtev_logic_ast_strndup(mtev_logic_ast_t *ast, const char *in, size_t inl) {
  char *copy = mtev_logic_ast_alloc(ast, inl+1, NULL);
  memcpy(copy, in, inl);
  copy[inl] = '\0';
  return copy;
}
static inline void *
mtev_logic_ast_strndup_unescape(mtev_logic_ast_t *ast, const char *in, size_t inl) {
  char *copy = mtev_logic_ast_strndup(ast, in, inl);
  char *writep = copy;
  for(char *cp = copy; *cp; cp++) {
    if(*cp != '\\') (*writep++) = *cp;
    else {
      switch(cp[1]) {
        /* [abefnrtv'"\\] */
        case 'a': (*writep++) = '\a'; cp++; break;
        case 'b': (*writep++) = '\b'; cp++; break;
        case 'e': (*writep++) = '\e'; cp++; break;
        case 'f': (*writep++) = '\f'; cp++; break;
        case 'n': (*writep++) = '\n'; cp++; break;
        case 'r': (*writep++) = '\r'; cp++; break;
        case 't': (*writep++) = '\t'; cp++; break;
        case 'v': (*writep++) = '\v'; cp++; break;
        case '\'': (*writep++) = '\''; cp++; break;
        case '"': (*writep++) = '"'; cp++; break;
        case '\\': (*writep++) = '\\'; cp++; break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
          *writep = cp[1] - '0';
          cp++;
          if(cp[1] >= '0' && cp[1] <= '7') {
            *writep *= 8;
            *writep += cp[1] - '0';
            cp++;
          }
          if(cp[-1] <= '3' && cp[1] >= '0' && cp[1] <= '7') {
            *writep *= 8;
            *writep += cp[1] - '0';
            cp++;
          }
          writep++;
          break;
      }
    }
  }
  *writep = '\0';
  return copy;
}
static inline void *
mtev_logic_ast_var(mtev_logic_ast_t *ast, mtev_logic_var_type_t vartype, const char *in, size_t inl) {
  mtev_logic_var_t *var = mtev_logic_ast_alloc(ast, sizeof(*var), mtev_logic_var_clean);
  memset(var, 0, sizeof(*var));
  var->type = vartype;
  if(vartype == MTEV_LOGIC_STRING) {
    /* these are escaped */
    var->value.s = mtev_logic_ast_strndup_unescape(ast, in, inl);
  } else {
    var->value.s = mtev_logic_ast_strndup(ast, in, inl);
  }
  var->value.n = strtod(var->value.s, NULL);
  var->value.l = strtoll(var->value.s, NULL, 10);
  return var;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "mtev-logic-leg.c"
#pragma GCC diagnostic pop

mtev_logic_ast_t *
mtev_logic_parse(const char *input, char **error) {
  mtev_logic_init();
  yycontext ctx;
  memset(&ctx, 0, sizeof(yycontext));
  ctx.ast = calloc(1, sizeof(*ctx.ast));
  ctx.input_buffer = input;
  ctx.input_buffer_len = strlen(input);
  ctx.error = error;
  while(yyparse(&ctx)) {

  }
  if(ctx.input_buffer_len != ctx.input_buffer_readidx) {
    if(asprintf(error, "failed to parse at character offset: %zu", ctx.input_buffer_readidx) == -1) {
      *error = strdup("error parsing");
    }
    mtev_logic_ast_free(ctx.ast);
    ctx.ast = NULL;
  }
  yyrelease(&ctx);
  return ctx.ast;
}

void
mtev_logic_ast_free(mtev_logic_ast_t *ast) {
  struct alloc_list *tofree;
  while(NULL != (tofree = ast->allocations)) {
    if(tofree->clean) tofree->clean(tofree->obj);
    free(tofree->obj);
    ast->allocations = tofree->next;
    free(tofree);
  }
  free(ast);
}

mtev_logic_exec_t *
mtev_logic_exec_alloc(const mtev_logic_ops_t *ops) {
  mtev_logic_init();
  mtev_logic_exec_t *exec = calloc(1, sizeof(*exec));
  exec->ops = ops;
  return exec;
}

void
mtev_logic_exec_free(mtev_logic_exec_t *exec) {
  free(exec);
}

static inline int strllcmp(const char *l, size_t ls, const char *r, size_t rs) {
  size_t s = MIN(ls, rs);
  int rv = memcmp(l, r, s);
  if(rv) return rv;
  if(ls < rs) return -1;
  return rs > ls;
}
static mtev_boolean
mtev_logic_exec_predicate(mtev_logic_exec_t *exec, mtev_logic_pred_t *pred, void *context) {
  mtev_logic_var_t lhs;
  size_t lhs_len = 0;
  memset(&lhs, 0, sizeof(lhs));
  mtev_boolean lhs_found = exec->ops->lookup(context, pred->left, &lhs);
  mtev_boolean match = mtev_false;
  if(pred->op == POP_EXISTS) {
    mtevL(debugls, "exists(%s) -> %s\n", pred->left, lhs_found ? "true" : "false");
    return lhs_found;
  }
  if(!lhs_found || (lhs.type == MTEV_LOGIC_STRING && lhs.value.s == NULL)) {
    match = (pred->op == POP_NE || pred->op == POP_NRE);
    mtevL(debugls, "!%s %s %s -> %s\n", pred->left, mtev_logic_pred_op_name(pred->op),
          pred->right->value.s, match ? "true" : "false");
    return match;
  }
  if(pred->right->type == MTEV_LOGIC_STRING) {
    int ovector[30];
    size_t rhs_len = 0;
    const char *lval = mtev_logic_var_tostring(&lhs, &lhs_len);
    const char *rval = mtev_logic_var_tostring(pred->right, &rhs_len);
    switch(pred->op) {
      case POP_EQ: match = 0 == strllcmp(lhs.value.s, lhs_len, rval, rhs_len); break;
      case POP_NE: match = 0 != strllcmp(lhs.value.s, lhs_len, rval, rhs_len); break;
      case POP_GE: match = strllcmp(lhs.value.s, lhs_len, rval, rhs_len) >= 0; break;
      case POP_GT: match = strllcmp(lhs.value.s, lhs_len, rval, rhs_len) > 0; break;
      case POP_LE: match = strllcmp(lhs.value.s, lhs_len, rval, rhs_len) <= 0; break;
      case POP_LT: match = strllcmp(lhs.value.s, lhs_len, rval, rhs_len) < 0; break;
      case POP_RE:
      case POP_NRE:
        if (pcre_exec(pred->right->re, pred->right->re_extra, lval, lhs_len, 0, 0, ovector, 30) >= 0) {
          match = (pred->op == POP_RE);
          break;
        }
        match = !(pred->op == POP_RE);
        break;
      case POP_EXISTS: mtevAssert(pred->op != POP_EXISTS);
    }
  } else {
    if(lhs.type == MTEV_LOGIC_STRING) {
      char ntcopy[128];
      /* We need to convert it */
      if(lhs.s_len < sizeof(ntcopy)) {
        memcpy(ntcopy, lhs.value.s, lhs.s_len);
        ntcopy[lhs.s_len] = '\0';
      }
      char *endptr = NULL;
      lhs.value.l = strtoll(ntcopy, &endptr, 10);
      if(*endptr == '\0') {
        lhs.type = MTEV_LOGIC_INT64;
      }
      else {
        lhs.value.n = strtod(ntcopy, &endptr);
        if(*endptr == '\0') {
          lhs.type = MTEV_LOGIC_DOUBLE;
        }
      }
    }
    if(lhs.type == MTEV_LOGIC_STRING) match = mtev_false;
    else {
      // lhs and pred->right are both numeric.
      // If either are doubles, we must degrade both to doubles.
#define DOMATCH(op,l,r) do { \
  switch(op) { \
    case POP_EQ: match = (l == r); break; \
    case POP_NE: match = (l != r); break; \
    case POP_GE: match = (l >= r); break; \
    case POP_GT: match = (l > r); break; \
    case POP_LE: match = (l <= r); break; \
    case POP_LT: match = (l < r); break; \
    default: mtevAssert(op == POP_EQ); \
  } \
} while(0)
      if(lhs.type == MTEV_LOGIC_DOUBLE || pred->right->type == MTEV_LOGIC_DOUBLE) {
        double l = (lhs.type == MTEV_LOGIC_DOUBLE) ? lhs.value.n : (double)lhs.value.l,
               r = (pred->right->type == MTEV_LOGIC_DOUBLE) ? pred->right->value.n : (double)pred->right->value.l;
        DOMATCH(pred->op, l, r);
      }
      else {
        int64_t l = lhs.value.l, r = pred->right->value.l;
        DOMATCH(pred->op, l, r);
      }
    }
  }
  mtevL(debugls, "%s[%s] %s %s[%s] -> %s\n",
        mtev_logic_var_type_name(lhs.type), mtev_logic_var_tostring(&lhs,NULL),
        mtev_logic_pred_op_name(pred->op),
        mtev_logic_var_type_name(pred->right->type), mtev_logic_var_tostring(pred->right,NULL),
        match ? "true" : "false");
  return match;
}
static mtev_boolean
mtev_logic_exec_node(mtev_logic_exec_t *exec, mtev_logic_node_t *node, void *context) {
  switch(node->logical_op) {
    case LOP_PREDICATE: return mtev_logic_exec_predicate(exec, node->predicate, context);
    case LOP_NOT: return !mtev_logic_exec_node(exec, node->elems[0], context);
    case LOP_AND:
      for(int i=0; i<node->nelems; i++) {
        if(!mtev_logic_exec_node(exec, node->elems[i], context)) return mtev_false;
      }
      return mtev_true;
    case LOP_OR:
      for(int i=0; i<node->nelems; i++) {
        if(mtev_logic_exec_node(exec, node->elems[i], context)) return mtev_true;
      }
      return mtev_false;
  }
  return mtev_false;
}

static mtev_boolean
mtev_logic_node_has_predicate(mtev_logic_node_t *n, const char *lval) {
  if(n->logical_op == LOP_PREDICATE && !strcmp(n->predicate->left, lval)) return mtev_true;
  for(int i=0; i<n->nelems; i++) {
    if(mtev_logic_node_has_predicate(n->elems[i], lval)) return mtev_true;
  }
  return mtev_false;
}
mtev_boolean
mtev_logic_has_predicate(mtev_logic_ast_t *ast, const char *lval) {
  return mtev_logic_node_has_predicate(ast->root, lval);
}

mtev_boolean
mtev_logic_exec(mtev_logic_exec_t *exec, mtev_logic_ast_t *ast, void *context) {
  return mtev_logic_exec_node(exec, ast->root, context);
}

static void
mtev_logic_node_log(mtev_log_stream_t l, mtev_logic_node_t *n, int level) {
  switch(n->logical_op) {
    case LOP_PREDICATE:
      if(n->predicate->right) {
        mtevL(l, "%*spredicate('%s' %s '%s')\n", level*2, "", n->predicate->left,
              mtev_logic_pred_op_name(n->predicate->op), n->predicate->right->value.s);
      } else {
        mtevL(l, "%*spredicate(%s '%s')\n", level*2, "",
              mtev_logic_pred_op_name(n->predicate->op), n->predicate->left);
      }
      break;
    case LOP_AND:
    case LOP_OR:
    case LOP_NOT:
      mtevL(l, "%*s%s(\n", level*2, "", mtev_logic_op_name(n->logical_op));
      for(int i=0; i<n->nelems; i++) {
        mtev_logic_node_log(l, n->elems[i], level+1);
      }
      mtevL(l, "%*s)\n", level*2, "");
      break;
  }
}
void
mtev_logic_ast_log(mtev_log_stream_t l, mtev_logic_ast_t *ast) {
  mtev_logic_node_log(l, ast->root, 0);
}
