/*************************************************************************
 *  TinyFugue - programmable mud client
 *  Copyright (C) 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2002, 2003, 2004, 2005, 2006-2007 Ken Keys
 *
 *  TinyFugue (aka "tf") is protected under the terms of the GNU
 *  General Public License.  See the file "COPYING" for details.
 ************************************************************************/

#ifndef EXPAND_H
#define EXPAND_H

/* note: these numbers must agree with enum_subs[] in variable.c. */
#define SUB_LITERAL -1  /* send literally (no /command interpretation, even) */
#define SUB_KEYWORD  0  /* SUB_NEWLINE if initial keyword, else no subs      */
#define SUB_NEWLINE  1  /* %; subs and command execution                     */
#define SUB_FULL     2  /* all subs and command execution                    */
#define SUB_MACRO    3  /* all subs and command execution, from macro        */

#if 0
typedef struct {
    Program *prog;
    int ip;		/* instruction pointer */
    String *cmd;
} Process;
#endif

typedef struct ProgContext {
    struct Sock *sock;
    unsigned long generation;
    int cancelled;
    struct ProgContext *parent;
    struct ProgContext *previous_active;
} ProgContext;

extern void init_expand(void);
extern void prog_free(Program *prog);
extern int prog_run(const Program *prog, const String *args, int offset,
    const char *name, int kbnumlocal);
extern struct Program *compile_tf(conString *body, int bodystart, int subs,
    int is_expr, int optimize);
extern int macro_run(conString *body, int boffset, String *args, int offset,
    int subs, const char *name);
extern Value *prog_interpret(const Program *prog, int in_expr);
extern ProgContext *push_socket_prog_context(ProgContext *context,
    struct Sock *sock, unsigned long generation);
extern ProgContext *push_dependent_socket_prog_context(ProgContext *context,
    struct Sock *sock, unsigned long generation);
extern ProgContext *suspend_prog_context(void);
extern void restore_prog_context(ProgContext *context);
extern void abort_prog_interpreters(struct Sock *sock,
    unsigned long generation);
extern int revalidate_prog_context_socket(struct Sock *sock,
    unsigned long generation);
extern int current_prog_context_cancelled(void);
extern int current_prog_context_active(void);
extern int prog_context_cancelled(const ProgContext *context);
extern String *do_mprefix(void);
extern const char **keyword(const char *id);
extern void eat_newline(Program *prog);
extern void eat_space(Program *prog);


#if USE_DMALLOC
extern void   free_expand(void);
#endif

extern struct Value *user_result;
extern const char *current_command;
extern int recur_count, breaking;

#define return_user_result() do { \
        struct Value *v = user_result; \
        user_result = NULL; \
        return v; \
    } while (0)

#define set_user_result(val)  do { \
	Value *tmp = val; /* evaluate val once, before freeing user_result */ \
        freeval(user_result); user_result = tmp; \
    } while(0)

#endif /* EXPAND_H */
