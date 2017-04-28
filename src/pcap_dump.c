#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <pcap/pcap.h>
#include <zmq.h>
#include <signal.h>

#include <linux/if_packet.h>

#include "common.h"
#include "pcap_dump.h"
#include "print_packet.h"
#include "zeromq.h"

static void *zmq_sock;

extern
void write_pcap(pcap_dumper_t *pcap_dumper, const u_char *h, const u_char *p)
{
    int rc;

    if(pcap_dumper != NULL && p != NULL) {
        pcap_dump((u_char *)pcap_dumper, (const struct pcap_pkthdr *)h, p);
    } else {
        warn_print("pcap dumper not available");
    }
}

extern
void teardown_pcap(pcap_dumper_t *pcap_dumper)
{
    int rc;

    rc = pcap_dump_flush(pcap_dumper);
    if (rc != 0) {
        err_print("pcap_dump_flush (%d): %s", errno, strerror(errno));
    }
    
    debug_print("closing pcap");
    pcap_dump_close(pcap_dumper);
}

extern
pcap_dumper_t* setup_pcap(char* pcap_file)
{
    pcap_t *p = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65535, PCAP_TSTAMP_PRECISION_NANO);
    pcap_dumper_t *pcap_dumper = pcap_dump_open(p, pcap_file);

    if(pcap_dumper == NULL) {
        err_print("pcap_dump_open failed: %s", pcap_geterr(p));
        return NULL;
    } else {
        info_print("setup_pcap pcap dump to '%s'", pcap_file);
    }

    return pcap_dumper;
}

static inline void setup_zmq_sub(char * addr) {
    int rc;

    info_print("%s started", __FUNCTION__);

    zqm_wait_for_context(zmq_context);

    zmq_sock = zmq_socket (zmq_context, ZMQ_SUB);
    if(zmq_sock == NULL ) {
        err_print("zmq_socket failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    info_print("connecting to '%s'", addr);
    rc = zmq_connect (zmq_sock, addr);
    if (rc != 0) {
        err_print("zmq_connect zmq_sock failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_SUBSCRIBE, "", 0);
    if (rc != 0) {
        err_print("ZMQ_SUBSCRIBE failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    zmq_setsockopt_func(zmq_sock);
    zmq_getsockopt_values(zmq_sock);

    info_print("%s completed", __FUNCTION__);
}

extern
void* start_pcap_dump() {
    int rc;

    debug_print("%s called", __FUNCTION__);
    pthread_cleanup_push((void *)thread_exit_func, (char *)(uintptr_t) __FUNCTION__);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
    }

    rc = mallopt(M_CHECK_ACTION, 1);
    if (rc != 1) {
        err_print("mallopt() failed (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
        goto error;
    }

    zqm_wait_for_context(zmq_context);

    pcap_dumper_t *pcap_dumper = setup_pcap("./pcap.pcap");
    if (pcap_dumper == NULL) {
        err_print("faile to setup pcap_dumper");
        raise(SIGTERM);
        goto error;
    }

    pthread_cleanup_push((void *)teardown_pcap, pcap_dumper);

    setup_zmq_sub("inproc://capture");
    pthread_cleanup_push((void *)teardown_zmq_sock, zmq_sock);

    info_print("%s entering main loop", __FUNCTION__);

    while(!needQuit(&do_shutdown)) {
        pthread_testcancel();

        zmq_msg_t msg;
        zmq_msg_init(&msg);

        int recieved_bytes = zmq_msg_recv (&msg, zmq_sock, 0);
        if (recieved_bytes == -1) {
            int errn = zmq_errno();
            switch(errn) {
                case EAGAIN:
                    usleep(100000);
                    goto free_msg;
                default:
                    warn_print("zmq_msg_recv failed (%d): %s", errn, zmq_strerror(errn));
                    usleep(100000);
                    goto free_msg;
            }
        }

        struct tpacket3_hdr *ppd = malloc_or_die(recieved_bytes);
        memcpy(ppd, zmq_msg_data(&msg), recieved_bytes);

        u_char* pkt = (u_char *)((uint8_t *) ppd + ppd->tp_mac);
        struct pcap_pkthdr *pcaphdr = (struct pcap_pkthdr *) malloc_or_die(sizeof(struct pcap_pkthdr));
        if(pcaphdr == NULL) {
            err_print("could not allocate memory for pcap_pkthdr (%d): %s", errno, strerror(errno));
            goto free_ppd;
        }

        pcaphdr->ts.tv_sec = ppd->tp_sec;
        pcaphdr->ts.tv_usec = ppd->tp_nsec / 1000;
        pcaphdr->caplen = ppd->tp_snaplen;
        pcaphdr->len = ppd->tp_len;

        write_pcap(pcap_dumper, (u_char *)pcaphdr, pkt);

free_ppd:
        insane_free(ppd);
        insane_free(pcaphdr);
free_msg:
        zmq_msg_close(&msg);
    }

// int pcap_stats(pcap_t *p, struct pcap_stat *ps);

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_cleanup_pop(3);

    pthread_exit(0);
}