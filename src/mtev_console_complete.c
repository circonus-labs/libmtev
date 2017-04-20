/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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

#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_listener.h"
#include "mtev_console.h"
#include "mtev_tokenizer.h"

#include "noitedit/sys.h"
#include "noitedit/el.h"
#include "noitedit/fcns.h"
#include "noitedit/map.h"

typedef char *NCPFunction(EditLine *, const char *, int);

char *
mtev_console_opt_delegate(mtev_console_closure_t ncct,
                          mtev_console_state_stack_t *stack,
                          mtev_console_state_t *state,
                          int argc, char **argv,
                          int idx) {
  int i;
  mtev_skiplist_node *next, *curr;
  cmd_info_t *cmd;

  if(state == NULL) return NULL;
  i = 0;
  if(argc == 0) {
    for(next = mtev_skiplist_getlist(&state->cmds); next;
        mtev_skiplist_next(&state->cmds,&next)) {
      cmd = next->data;
      if(idx == i) return strdup(cmd->name);
      i++;
    }
  }

  cmd = mtev_skiplist_find_neighbors(&state->cmds, argv[0],
                                     NULL, &curr, &next);
  if(cmd) {
    if(argc != 1) {
      if(!cmd->autocomplete) return NULL;
      return cmd->autocomplete(ncct, stack, cmd->dstate, argc-1, argv+1, idx);
    }
    next = curr;
    goto multiples;
  }

 multiples:
  if(!next) return NULL;
  i = 0;
  while(next) {
    cmd = next->data;
    if(cmd && strncasecmp(cmd->name, argv[0], strlen(argv[0])) == 0) {
      if(idx == i) return strdup(cmd->name);
      i++;
    }
    mtev_skiplist_next(&state->cmds, &next);
  }
  return NULL;
}


static char *
noitedit_completion_function(EditLine *el, const char *text, int state) {
  mtev_console_closure_t ncct;
  const LineInfo *li;
  char **cmds, *curstr, *rv = NULL;
  int len, cnt = 32;

  li = el_line(el);
  len = li->cursor - li->buffer;
  curstr = alloca(len + 1);
  memcpy(curstr, li->buffer, len);
  curstr[len] = '\0';

  cmds = alloca(32 * sizeof(*cmds));
  cmds[0] = NULL;
  (void) mtev_tokenize(curstr, cmds, &cnt);

  el_get(el, EL_USERDATA, (void *)&ncct);

  if(!strlen(text)) {
    cmds[cnt++] = strdup("");
  }
  if(cnt != 32)
    rv = mtev_console_opt_delegate(ncct, ncct->state_stack,
                                   ncct->state_stack->state,
                                   cnt, cmds, state);
  if(cmds[0]) while(cnt > 0) free(cmds[--cnt]);
  return rv;
}
static int
_edit_qsort_string_compare(const void *i1, const void *i2)
{
        /*LINTED const castaway*/
        const char *s1 = ((const char **)i1)[0];
        /*LINTED const castaway*/
        const char *s2 = ((const char **)i2)[0];

        return strcasecmp(s1, s2);
}
static char **
completion_matches(EditLine *el, const char *text, NCPFunction *genfunc) {
  char **match_list = NULL, *retstr, *prevstr;
  size_t match_list_len, max_equal, which, i;
  int matches;

  matches = 0;
  match_list_len = 1;
  while ((retstr = (*genfunc) (el, text, matches)) != NULL) {
    if(matches + 1 >= match_list_len) {
      match_list_len <<= 1;
      match_list = realloc(match_list,
                           match_list_len * sizeof(char *));
    }
    match_list[++matches] = retstr;
  }

  if(!match_list)
    return (char **) NULL;  /* nothing found */

  /* find least denominator and insert it to match_list[0] */
  which = 2;
  prevstr = match_list[1];
  max_equal = strlen(prevstr);
  for(; which <= matches; which++) {
    for(i = 0; i < max_equal && prevstr[i] == match_list[which][i]; i++)
      continue;
    max_equal = i;
  }

  retstr = malloc(max_equal + 1);
  (void) strncpy(retstr, match_list[1], max_equal);
  retstr[max_equal] = '\0';
  match_list[0] = retstr;

  /* add NULL as last pointer to the array */
  if(matches + 1 >= match_list_len)
    match_list = realloc(match_list,
                         (match_list_len + 1) * sizeof(char *));
  match_list[matches + 1] = (char *) NULL;

  return (match_list);
}

static void
mtev_edit_display_match_list (EditLine *el, char **matches, int len, int max)
{
  int i, idx, limit, count;
  int screenwidth = el->el_term.t_size.h;

  /*
   * Find out how many entries can be put on one line, count
   * with two spaces between strings.
   */
  limit = screenwidth / (max + 2);
  if(limit == 0)
    limit = 1;

  /* how many lines of output */
  count = len / limit;
  if(count * limit < len)
    count++;

  /* Sort the items if they are not already sorted. */
  qsort(&matches[1], (size_t)(len - 1), sizeof(char *),
        _edit_qsort_string_compare);

  idx = 1;
  for(; count > 0; count--) {
    for(i=0; i < limit && matches[idx]; i++, idx++)
      el->el_std_printf(el, "%-*s  ", max, matches[idx]);
    el->el_std_printf(el, "\r\n");
  }
}

unsigned char
mtev_edit_complete(EditLine *el, int invoking_key) {
  static const char *rl_basic_word_break_characters = " \t\n\"\\'@$><=;|&{(";
  static const char *rl_special_prefixes = NULL;
  static const int   rl_completion_append_character = ' ';
  mtev_console_closure_t ncct;
  const LineInfo *li;
  char *temp, **matches;
  const char *ctemp;
  int method = '\t';
  size_t len;

  el_get(el, EL_USERDATA, (void *)&ncct);

  if(el->el_state.lastcmd == ncct->mtev_edit_complete_cmdnum)
    method = '?';

  /* We now look backwards for the start of a filename/variable word */
  li = el_line(el);
  ctemp = (const char *) li->cursor;
  while (ctemp > li->buffer
      && !strchr(rl_basic_word_break_characters, ctemp[-1])
      && (!rl_special_prefixes
      || !strchr(rl_special_prefixes, ctemp[-1]) ) )
    ctemp--;

  len = li->cursor - ctemp;
  temp = alloca(len + 1);
  (void) strncpy(temp, ctemp, len);
  temp[len] = '\0';

  /* these can be used by function called in completion_matches() */
  /* or (*rl_attempted_completion_function)() */
  ncct->rl_point = li->cursor - li->buffer;
  ncct->rl_end = li->lastchar - li->buffer;

  matches = completion_matches(el, temp, noitedit_completion_function);

  if (matches) {
    int i, retval = CC_REFRESH;
    int matches_num, maxlen, match_len;

    /*
     * Only replace the completed string with common part of
     * possible matches if there is possible completion.
     */
    if (matches[0][0] != '\0') {
      el_deletestr(el, (int) len);
      el_insertstr(el, matches[0]);
    }

    if (method == '?')
      goto display_matches;

    if (matches[2] == NULL && strcmp(matches[0], matches[1]) == 0) {
      /*
       * We found exact match. Add a space after
       * it, unless we do filename completition and the
       * object is a directory.
       */
      size_t alen = strlen(matches[0]);
      if ((alen > 0 && (matches[0])[alen - 1] != '/')) {
        char buf[2];
        buf[0] = rl_completion_append_character;
        buf[1] = '\0';
        el_insertstr(el, buf);
      }
    } else if (method == '!') {
    display_matches:
      /*
       * More than one match and requested to list possible
       * matches.
       */

      for(i=1, maxlen=0; matches[i]; i++) {
        match_len = strlen(matches[i]);
        if (match_len > maxlen)
          maxlen = match_len;
      }
      matches_num = i - 1;
        
      /* newline to get on next line from command line */
      el->el_std_printf(el, "\r\n");

      mtev_edit_display_match_list(el, matches, matches_num, maxlen);
      retval = CC_REDISPLAY;
    } else if (matches[0][0]) {
      /*
       * There was some common match, but the name was
       * not complete enough. Next tab will print possible
       * completions.
       */
      el_beep(el);
    } else {
      /* lcd is not a valid object - further specification */
      /* is needed */
      el_beep(el);
      retval = CC_NORM;
    }

    /* free elements of array and the array itself */
    for (i = 0; matches[i]; i++)
      free(matches[i]);
    free(matches), matches = NULL;

    return (retval);
  }
  return (CC_NORM);
}
