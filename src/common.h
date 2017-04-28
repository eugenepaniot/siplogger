#ifndef DEBUG
#define DEBUG 1
#endif

#ifndef EXTRADEBUG
#define EXTRADEBUG 0
#endif

#ifndef ALARM_SLEEP
#define ALARM_SLEEP 1
#endif

#define _MULTI_THREADED

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET "\033[0m"

#define insane_free(p) { if(p) { free(p); p = 0; } }

#define print_bt(f) do {\
        char **bts = malloc(sizeof(char)); \
        int nptrs = get_backtrace(&bts); \
        for (int i=0; i < nptrs; i++) \
            f("%d: %s", i, bts[i]);\
    } while (0)

#define info_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        pid_t pid = getpid(); \
        fprintf(stdout, KGRN "[INFO (%u:%u) %s: %s:(%d)]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __FILE__, __LINE__, ## ARGS); \
    } while (0)

#define warn_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        pid_t pid = getpid(); \
        fprintf(stderr, KYEL "[WARN (%u:%u) %s: %s:(%d)]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __FILE__, __LINE__, ## ARGS); \
    } while (0)

#define error_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        pid_t pid = getpid(); \
        fprintf(stderr, KRED "[ERROR (%u:%u) %s: %s:(%d)]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __FILE__, __LINE__, ## ARGS); \
    } while (0)

#define err_print(FMT, ARGS...) do { \
        print_bt(error_print); \
        error_print(FMT, ## ARGS);\
    } while (0)

#define debug_print(FMT, ARGS...) do { \
        if (DEBUG) { \
            pid_t ptid = syscall(__NR_gettid); \
            pid_t pid = getpid(); \
            char **bts = malloc(sizeof(char)); \
            int nptrs = get_backtrace(&bts), np=-1; \
            for (int i=3; np < 0; i--) \
                np = nptrs-i;\
            fprintf(stdout, KBLU "[DEBUG (%u:%u) %s(%s): %s:(%d)]:\t " KNRM FMT "\n", pid, ptid, bts[np], __FUNCTION__, __FILE__, __LINE__, ## ARGS); \
            insane_free(bts); \
        } \
    } while (0)

#ifndef likely
#define likely(x)      __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)        __builtin_expect(!!(x), 0)
#endif

#define ALIGN_8(x)      (((x) + 8 - 1) & ~(8 - 1))

#define ARRAY_LEN(arr) ((int) (sizeof (arr) / sizeof (arr)[0]))


extern u_short verbose;
extern pthread_mutex_t do_shutdown;

extern int64_t clock_usecs (void);
extern long delta_time (struct timeval * now, struct timeval * before);
extern void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result);

extern int needQuit(pthread_mutex_t *mtx);
extern void thread_exit_func(void *arg);

extern
int get_backtrace(char *** strings);

extern
int printf_locked(const char *format, ...);

extern
int fprintf_locked(FILE *fp, const char *format, ...);

extern
int vprintf_locked(const char *format, va_list args);

extern
int vfprintf_locked(FILE *fp, const char *format, va_list args);

extern
void *malloc_or_die(size_t size);

