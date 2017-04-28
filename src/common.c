#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/types.h>
#include <jemalloc/jemalloc.h>
#include <features.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <features.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <zmq.h>
#include <inttypes.h>
#include <sys/time.h>
#include <ctype.h>
#include <wchar.h>
#include <sched.h>
#include <execinfo.h>

#include "common.h"

extern int64_t 
clock_usecs (void) {
    // 10^-6
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (int64_t) ((int64_t) ts.tv_sec * 1000000 + (int64_t) ts.tv_nsec / 1000);
}

extern long 
delta_time (struct timeval * now,
                 struct timeval * before) {
    time_t delta_seconds;
    time_t delta_microseconds;

    /*
     * compute delta in second, 1/10's and 1/1000's second units
     */
    delta_seconds      = now -> tv_sec  - before -> tv_sec;
    delta_microseconds = now -> tv_usec - before -> tv_usec;

    if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
    }
    return((delta_seconds * 1000000) + delta_microseconds);
}

extern
void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
  char          hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *result = (char *)malloc(binsz * 2 + 1);
  (*result)[binsz * 2] = 0;

  if (!binsz)
    return;

  for (i = 0; i < binsz; i++)
    {
      (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
      (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }  
}


/* Returns 1 (true) if the mutex is unlocked, which is the
 * thread's signal to terminate. 
 */
extern
int needQuit(pthread_mutex_t *mtx)
{
    switch(pthread_mutex_trylock(mtx)) {
        case 0: /* if we got the lock, unlock and return 1 (true) */
            pthread_mutex_unlock(mtx);
            return 1;
        case EBUSY: /* return 0 (false) if the mutex was locked */
            return 0;
    }

    return 1;
}

extern 
void thread_exit_func(void *arg) {
    info_print("thread '%s' exited", (char *) arg);
}

extern
int get_backtrace(char *** strings)
{
    int nptrs;
    void *buffer[1000];
    char **s;

    nptrs = backtrace(buffer, 1000);

    s = backtrace_symbols(buffer, nptrs);
    if (s == NULL) {
       perror("backtrace_symbols");
       raise(SIGTERM);
    }

    // for (j = 0; j < nptrs; j++)
    //    printf("%s \n", s[j]);

    memmove(strings, &s, sizeof(char) * nptrs);

    return nptrs;
}

extern
int printf_locked(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int rc = vfprintf_locked(stdout, format, args);
    va_end(args);
    return rc;
}
extern
int fprintf_locked(FILE *fp, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int rc = vfprintf_locked(fp, format, args);
    va_end(args);
    return rc;
}
extern
int vprintf_locked(const char *format, va_list args)
{
    return vfprintf_locked(stdout, format, args);
}
extern
int vfprintf_locked(FILE *fp, const char *format, va_list args)
{
    flockfile(fp);
    int rc = vfprintf(fp, format, args);
    funlockfile(fp);
    return rc;
}

extern
void *malloc_or_die(size_t size)
{
  void *p;

  if ((p = malloc(size))== NULL) {
    err_print("malloc failed");
    raise(SIGTERM);
    exit(1);
  }

  return p;
}

