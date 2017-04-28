#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <time.h>

#include <features.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <semaphore.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <zmq.h>
#include <sys/time.h>
#include <ctype.h>
#include <wchar.h>
#include <sched.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <ifaddrs.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "common.h"
#include "capture.h"
#include "zeromq.h"
#include "print_packet.h"
#include "pcap_dump.h"
#include "parser.h"

// https://git.zx2c4.com/linux/plain/tools/testing/selftests/net/psock_fanout.c
// http://www.cse.wustl.edu/~jain/cse567-11/ftp/pkt_recp/
// https://www.kernel.org/doc/Documentation/networking/timestamping.txt
// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
// http://lxr.free-electrons.com/source/tools/testing/selftests/net/psock_tpacket.c
// https://wiki.linuxfoundation.org/networking/kernel_flow
// https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-linux.c

#define start_thread(thr, ptr, arg, name) do { \
        static int rc; \
        info_print("starting thread: %s", name); \
        rc = pthread_create(&thr, NULL, (void * (*)(void *))ptr, (void *)(uintptr_t)arg); \
        if (rc != 0) { \
            err_print("pthread_create failed: (%d): %s", rc, strerror(rc)); \
            raise(SIGTERM); \
        }\
        rc = pthread_setname_np(thr, name); \
        if (rc != 0) \
            warn_print("pthread_setname_np failed: (%d): %s", rc, strerror(rc)); \
    } while (0)

static const char *device_name;

static pthread_t thread_zmq;
static pthread_t thread_capture;
static pthread_t thread_print_packet;
static pthread_t thread_pcap_dumper;
static pthread_t thread_parser;

static pthread_mutexattr_t mattr;
pthread_mutex_t do_shutdown;

struct ifaddrs **ifaddrs = NULL;

static void stop_threads();

static void main_exit(int s, void *arg) {
    int rc;

    rc = pthread_mutex_destroy(&do_shutdown);
    if (rc != 0)
        err_print("pthread_mutex_destroy failed: (%d): %s", rc, strerror(rc));
    else
        debug_print("pthread_mutex_destroy do_shutdown (%d): %s", rc, strerror(rc));

    rc = pthread_mutexattr_destroy(&mattr);
    if (rc != 0)
        err_print("pthread_mutexattr_destroy failed: (%d): %s", rc, strerror(rc));
    else
        debug_print("pthread_mutexattr_destroy mattr (%d): %s", rc, strerror(rc));

    info_print("exit status: %d", s);
}

static void sighandler(int signum)
{
    debug_print("%s called", __FUNCTION__);
    
    info_print("SIGNAL: %s(%d). Leaving.", strsignal(signum), signum);
    
    pthread_mutex_unlock(&do_shutdown);

    stop_threads();
}

static inline void stop_thread(pthread_t thr) 
{
    int rc;

    debug_print("%s called", __FUNCTION__);

    if(thr && pthread_kill(thr, 0) == 0) {
        static char name[32] = {};

        rc = pthread_getname_np(thr, name, sizeof(name));
        if (rc != 0)
            warn_print("pthread_getname_np failed: (%d): %s", rc, strerror(rc));
            
        debug_print("send pthread_cancel to '%s'", name);
        pthread_cancel(thr);
        
        debug_print("pthread_canceled '%s'", name);
    }
}

static inline void wait_thread(pthread_t thr) 
{
    void *t_join_res;
    int rc;

    debug_print("%s called", __FUNCTION__);

    if(thr && pthread_kill(thr, 0) == 0) {
        static char name[32] = {};

        rc = pthread_getname_np(thr, name, sizeof(name));
        if (rc != 0)
            warn_print("pthread_getname_np failed: (%d): %s", rc, strerror(rc));
        
        rc = pthread_join(thr, &t_join_res);
        if (rc != 0)
            warn_print("pthread_join on '%s' failed", name);

        if (t_join_res == PTHREAD_CANCELED)
            info_print("thread '%s' was canceled", name);
        else
            warn_print("thread '%s' was terminated normally", name);
    }
}

static void start_threads() 
{
    debug_print("%s called", __FUNCTION__);

    start_thread(thread_zmq, start_zeromq, NULL, "zeromq");
    start_thread(thread_capture, start_capture, device_name, "capture");
    
    start_thread(thread_print_packet, start_print_packet, NULL, "print_packet");
    start_thread(thread_pcap_dumper, start_pcap_dump, NULL, "pcap_dumper");
    start_thread(thread_parser, start_parser, NULL, "pcap_dumper");

    info_print("%s completed", __FUNCTION__);
}

static void stop_threads() 
{
    debug_print("%s called", __FUNCTION__);

    stop_thread(thread_zmq);
    stop_thread(thread_capture);
    stop_thread(thread_print_packet);
    stop_thread(thread_pcap_dumper);
    stop_thread(thread_parser);

    info_print("%s completed", __FUNCTION__);
}

static void wait_threads() 
{
    debug_print("%s called", __FUNCTION__);

    wait_thread(thread_zmq);
    wait_thread(thread_capture);
    wait_thread(thread_print_packet);
    wait_thread(thread_pcap_dumper);
    wait_thread(thread_parser);
}

int main(int argc, char **argp)
{
    int rc;

    if (argc != 2) {
        err_print("Usage: %s INTERFACE}\n", argp[0]);
        return EXIT_FAILURE;
    }

    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    device_name = argp[1];

    rc = mallopt(M_CHECK_ACTION, 1);
    if (rc != 1) {
        err_print("mallopt() failed (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }
    
    if (on_exit(main_exit, NULL) != 0) {
        err_print("on_exit failed");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    rc = pthread_mutexattr_init(&mattr);
    if (rc != 0) {
        err_print("pthread_mutexattr_init failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK_NP);
    if (rc != 0) {
        err_print("pthread_mutexattr_settype failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    if (rc != 0) {
        err_print("pthread_mutexattr_setpshared failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutex_init(&do_shutdown, &mattr);
    if (rc != 0) {
        err_print("pthread_mutex_init failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    pthread_mutex_lock(&do_shutdown);

    start_threads();

    info_print("%s entering main loop", __FUNCTION__);

    wait_threads();

    return 0;
}
