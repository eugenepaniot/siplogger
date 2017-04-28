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

#include "common.h"
#include "zeromq.h"

unsigned long long zmq_send_msq_total = 0, zmq_send_msq_total_failed = 0, zmq_send_bytes_total = 0;

int zmq_linger_time = 1000;
int zmq_hwm_msg = 1000;
int zmq_sndtimeo = 100;
void *zmq_context = NULL;

// static void print_stats() {
//     fflush(stdout);
//     info_print("stats: received total: %llu msg, bytes total: %llu, failed total: %llu msg",
//            zmq_send_msq_total, zmq_send_bytes_total,
//            zmq_send_msq_total_failed);

//     return;
// }

extern void zqm_wait_for_context() {
    debug_print("%s called", __FUNCTION__);

    for(int i=1; zmq_context == NULL && i <= 5 && !needQuit(&do_shutdown); i++) {
        warn_print("zmq_context not ready. Await %d seconds", i);
        sleep(i);
        __sync_synchronize();
    }

    if(zmq_context == NULL) {
        err_print("zmq_context failed");
        raise(SIGTERM);
    }

    info_print("%s completed", __FUNCTION__);
}

extern 
int send_to_zmq(void *zmq_sock, void * data, u_int len, int flags) 
{
    int rc;
    zmq_msg_t msg;
    
    __sync_fetch_and_add(&zmq_send_msq_total, 1);

    rc = zmq_msg_init_data(&msg, data, len, NULL, NULL);
    if (rc != 0) {
        warn_print("zmq_msg_init_data failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        goto fail;
    }

    rc = zmq_msg_send (&msg, zmq_sock, flags);
    if (rc == -1) {
        warn_print("zmq_send failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        goto fail;
    }

    __sync_fetch_and_add(&zmq_send_bytes_total, rc);

    return rc;

fail:
    __sync_fetch_and_add(&zmq_send_msq_total_failed, 1);
    
    return rc;    
}

extern 
void zmq_getsockopt_values(void *zmq_sock) {
    int zmq_getsockopt_value, rc;
    size_t zmq_getsockopt_value_size = sizeof (zmq_getsockopt_value);

    char zmq_getsockopt_value_char[512];
    size_t zmq_getsockopt_value_char_size = sizeof (zmq_getsockopt_value_char);

    debug_print("%s called", __FUNCTION__);

    rc = zmq_getsockopt (zmq_sock, ZMQ_TYPE, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_TYPE failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_TYPE: %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_SNDHWM, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_SNDHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_SNDHWM (Retrieves high water mark for outbound messages): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_RCVHWM, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_RCVHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_RCVHWM (Retrieve high water mark for inbound messages): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_LINGER, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_LINGER failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_LINGER (Retrieve linger period for socket shutdown): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_RCVTIMEO, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_RCVTIMEO (Maximum time before a socket operation returns with EAGAIN): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_SNDTIMEO, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_SNDTIMEO (Maximum time before a socket operation returns with EAGAIN): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_sock, ZMQ_LAST_ENDPOINT, &zmq_getsockopt_value_char, &zmq_getsockopt_value_char_size);
    if (rc != 0) {
        warn_print("ZMQ_LAST_ENDPOINT failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_LAST_ENDPOINT: %s", zmq_getsockopt_value_char);
    }
}

extern
void zmq_setsockopt_func(void *zmq_sock) {
    int rc;
    int opt = 1;

    debug_print("%s called", __FUNCTION__);

    rc = zmq_setsockopt(zmq_sock, ZMQ_LINGER, &zmq_linger_time, sizeof(zmq_linger_time));
    if (rc != 0) {
        err_print("ZMQ_LINGER failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_SNDHWM, &zmq_hwm_msg, sizeof(zmq_hwm_msg));
    if (rc != 0) {
        err_print("ZMQ_SNDHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_RCVHWM, &zmq_hwm_msg, sizeof(zmq_hwm_msg));
    if (rc != 0) {
        err_print("ZMQ_RCVHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_RCVTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_DELAY_ATTACH_ON_CONNECT, &opt, sizeof(opt));
    if (rc != 0) {
        err_print("ZMQ_DELAY_ATTACH_ON_CONNECT failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }
}

extern
void zmq_ctx_destroy_func(void *zmq_ctx) {
    int rc;
    debug_print("%s called", __FUNCTION__);

    rc = zmq_ctx_term(zmq_ctx);
    if (rc != 0) {
        err_print("zmq_ctx_destroy failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_ctx_destroy: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    }
    
    __sync_synchronize();
}

extern 
void zmq_ctx_set_opts (void *zmq_ctx) {
    int rc;
    int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

    debug_print("%s called", __FUNCTION__);

    rc = zmq_ctx_set(zmq_ctx, ZMQ_IO_THREADS, numCPU);
    if (rc != 0)
        warn_print("zmq_ctx_set failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    
    rc = zmq_ctx_set(zmq_ctx, ZMQ_MAX_SOCKETS, 4096);
    if (rc != 0)
        warn_print("zmq_ctx_set failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
}

extern 
void zmq_ctx_get_opts (void *zmq_ctx) {
    int intv;
    debug_print("%s called", __FUNCTION__);

    intv = zmq_ctx_get (zmq_ctx, ZMQ_IO_THREADS); 
    if (intv < 0) {
        warn_print("zmq_ctx_get failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_IO_THREADS: %d", intv);
    }

    intv = zmq_ctx_get (zmq_ctx, ZMQ_MAX_SOCKETS); 
    if (intv < 0) {
        warn_print("zmq_ctx_get failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("ZMQ_MAX_SOCKETS: %d", intv);
    }

}

extern void teardown_zmq_sock(void *zmq_sock) {
    int rc;
    info_print("%s started", __FUNCTION__);

    rc = zmq_close(zmq_sock);
    if (rc != 0) {
        warn_print("zmq_close failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_close closed");
        zmq_sock = NULL;
    }

    info_print("%s completed", __FUNCTION__);
}

extern
void start_zeromq() {
    int rc;

    debug_print("%s called", __FUNCTION__);

    pthread_cleanup_push((void *)thread_exit_func, (char *)(uintptr_t) __FUNCTION__);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0)
        warn_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));

    int zmq_major, zmq_minor, zmq_patch;
    zmq_version (&zmq_major, &zmq_minor, &zmq_patch);
    info_print ("using 0MQ version: %d.%d.%d", zmq_major, zmq_minor, zmq_patch);

    if(zmq_major != 4) {
        err_print("0MQ 4.x.x version reqired");
        raise(SIGTERM);
        goto error;
    }

    zmq_context = zmq_ctx_new();
    if (zmq_context == NULL) {
        err_print("zmq_ctx_new failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }
    
    zmq_ctx_set_opts(zmq_context);
    zmq_ctx_get_opts(zmq_context);

    __sync_synchronize();

    pthread_cleanup_push((void *)zmq_ctx_destroy_func, zmq_context);

    info_print("%s entering main loop", __FUNCTION__);
    
    pthread_testcancel();

    while(!needQuit(&do_shutdown)) {
        // print_stats();
        pthread_testcancel();
        sleep(1);
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);

    pthread_exit(0);
}