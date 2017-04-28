#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <zmq.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <sys/syscall.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/filter.h>
#include <linux/net_tstamp.h>

#include <pcap/pcap.h>

#include "common.h"
#include "capture.h"
#include "pcap_dump.h"
#include "zeromq.h"
#include "print_packet.h"

#define BLOCK_SIZE      (getpagesize() << 2)
#define FRAME_SIZE      (TPACKET_ALIGNMENT << 7)

#define NUM_BLOCKS      100
#define NUM_FRAMES      ((BLOCK_SIZE * NUM_BLOCKS) / FRAME_SIZE)

#define BLOCK_STATUS(x)     ((x)->h1.block_status)

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

// struct tpacket_req3 {
        // unsigned int    tp_block_size;  /* Minimal size of contiguous block */
        // unsigned int    tp_block_nr;    /* Number of blocks */
        // unsigned int    tp_frame_size;  /* Size of frame */
        // unsigned int    tp_frame_nr;    /* Total number of frames */
        // unsigned int    tp_retire_blk_tov; /* timeout in msecs */
        // unsigned int    tp_sizeof_priv; /* offset to private data area */
        // unsigned int    tp_feature_req_word;
// };

// struct tpacket3_hdr {
//         __u32           tp_next_offset;
//         __u32           tp_sec;
//         __u32           tp_nsec;
//         __u32           tp_snaplen;
//         __u32           tp_len;
//         __u32           tp_status;
//         __u16           tp_mac;
//         __u16           tp_net;
//         /* pkt_hdr variants */
//         union {
//                 struct tpacket_hdr_variant1 hv1;
//         };
// };

struct ring {
    struct iovec *rd;
    size_t mm_len, rd_len;
    uint8_t *map;
    int rd_num, flen;
    struct sockaddr_ll ll;
    struct tpacket_req3 req;
};

static int stat_sock;
static unsigned long long packets_total = 0, bytes_total = 0, dropped_total = 0;
static void *zmq_sock;

static int parse_bpf_filter(char *filter_buffer, u_int caplen, struct bpf_program *filter);

// static pcap_dumper_t *pcap_dumper;

static void print_stats() 
{
    socklen_t len;
    int rc;
    struct tpacket_stats_v3 stats;
    
    len = sizeof(stats);

    if (stat_sock) {
        rc = getsockopt(stat_sock, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
        if (rc != 0) {
            warn_print("getsockopt");
            return;
        }

        dropped_total += stats.tp_drops;

        fflush(stdout);
        info_print("stats: received: %u, total: %llu packets, bytes total: %llu, dropped: %u, total: %llu, freeze_q_cnt: %u",
               stats.tp_packets, packets_total,
               bytes_total,
               stats.tp_drops, dropped_total,
               stats.tp_freeze_q_cnt);

    } else {
        warn_print("stats failed sock not valid: %d", stat_sock);
    }

    return;
}

static void my_sigalarm()
{
    if(stat_sock)
        print_stats();

    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

static int setup_pfsocket(int ver)
{
    debug_print("%s called", __FUNCTION__);

    int rc;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock == -1) {
        err_print("socket AF_PACKET SOCK_RAW failed (%d): %s", errno, strerror(errno));
        raise(SIGTERM);

        exit(1);
    }

    rc = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    if (rc < 0) {
        err_print("socket PACKET_VERSION failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    }

    info_print("socket setup");

    return sock;
}

static void setup_filter(int sock) 
{
    int rc;

    debug_print("%s called", __FUNCTION__);

    struct bpf_program filter;

    rc = parse_bpf_filter("udp && port 5060", 65535, &filter);
    if (rc != 0) {
        err_print("parse_bpf_filter failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    }

    info_print("attaching BPF filter");

    struct bpf_insn *insn = filter.bf_insns;
    for (u_int i = 0; i < filter.bf_len; ++insn, ++i) {
        fprintf(stdout, "{ 0x%x, %d, %d, 0x%08x },\n", insn->code, insn->jt, insn->jf, insn->k);
    }

    struct sock_fprog linux_bpf = {
        .len = filter.bf_len,
        .filter = (struct sock_filter *) filter.bf_insns,
    };

    rc = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &linux_bpf, sizeof(linux_bpf));
    if (rc < 0) {
        err_print("socket SO_ATTACH_FILTER failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    }
}

// int enable_hw_timestamp(int sock, char *device_name, u_int8_t enable_rx, u_int8_t enable_tx) 
// {
//   struct hwtstamp_config hwconfig;
//   struct ifreq ifr;
//   int rc;

//   memset(&hwconfig, 0, sizeof(hwconfig));

//   hwconfig.rx_filter = (enable_rx ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE);
//   hwconfig.tx_type   = (enable_tx ? HWTSTAMP_TX_ON      : HWTSTAMP_TX_OFF);

//   memset(&ifr, 0, sizeof(ifr));
//   strncpy(ifr.ifr_name, device_name, sizeof(ifr.ifr_name)-1);

//   ifr.ifr_data = (void *) &hwconfig;

//   rc = ioctl(sock, SIOCSHWTSTAMP, &ifr);

//   if (rc < 0)
//     rc = errno;
//   else
//     rc = 0;

//   errno = 0;

//   return rc;
// }


/*
Frames are grouped in blocks. Each block is a physically contiguous
region of memory and holds tp_block_size/tp_frame_size frames. The total number 
of blocks is tp_block_nr. Note that tp_frame_nr is a redundant parameter because

    frames_per_block = tp_block_size/tp_frame_size

indeed, packet_set_ring checks that the following condition is true

    frames_per_block * tp_block_nr == tp_frame_nr

Lets see an example, with the following values:

     tp_block_size= 4096
     tp_frame_size= 2048
     tp_block_nr  = 4
     tp_frame_nr  = 8

we will get the following buffer structure:

        block #1                 block #2         
+---------+---------+    +---------+---------+    
| frame 1 | frame 2 |    | frame 3 | frame 4 |    
+---------+---------+    +---------+---------+    

        block #3                 block #4
+---------+---------+    +---------+---------+
| frame 5 | frame 6 |    | frame 7 | frame 8 |
+---------+---------+    +---------+---------+

A frame can be of any size with the only condition it can fit in a block. A block
can only hold an integer number of frames, or in other words, a frame cannot 
be spawned across two blocks, so there are some details you have to take into 
account when choosing the frame_size. See "Mapping and use of the circular 
buffer (ring)".

 Block number limit
--------------------

To understand the constraints of PACKET_MMAP, we have to see the structure 
used to hold the pointers to each block.

Currently, this structure is a dynamically allocated vector with kmalloc 
called pg_vec, its size limits the number of blocks that can be allocated.

    +---+---+---+---+
    | x | x | x | x |
    +---+---+---+---+
      |   |   |   |
      |   |   |   v
      |   |   v  block #4
      |   v  block #3
      v  block #2
     block #1

kmalloc allocates any number of bytes of physically contiguous memory from 
a pool of pre-determined sizes. This pool of memory is maintained by the slab 
allocator which is at the end the responsible for doing the allocation and 
hence which imposes the maximum memory that kmalloc can allocate. 

*/

static void setup_ring(struct ring *ring)
{
    debug_print("%s called", __FUNCTION__);

    memset(&ring->req, 0, sizeof(ring->req));

    ring->req.tp_retire_blk_tov = 64;
    ring->req.tp_sizeof_priv = 0;
    ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    ring->req.tp_block_size = BLOCK_SIZE;
    ring->req.tp_frame_size = FRAME_SIZE;
    ring->req.tp_block_nr = NUM_BLOCKS;

    ring->req.tp_frame_nr = NUM_FRAMES;

    ring->mm_len = ring->req.tp_block_size * ring->req.tp_block_nr;
    ring->rd_num = ring->req.tp_block_nr;
    ring->flen = ring->req.tp_block_size;

    info_print("Minimal size of contiguous block: %u", ring->req.tp_block_size);
    info_print("Number of blocks: %u", ring->req.tp_block_nr);

    info_print("Size of frame: %u", ring->req.tp_frame_size);
    info_print("Total number of frames: %u", ring->req.tp_frame_nr);

    info_print("Length of the mapp: %zu", ring->mm_len);
    info_print("Read operations (rd num): %u", ring->rd_num);
    info_print("Number of bytes to transfer (iovec->flen): %u", ring->flen);
}


static void mmap_ring(int sock, struct ring *ring)
{
    int i, rc;
    debug_print("%s called", __FUNCTION__);

    info_print("mmaping ring");

    rc = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req));
    if (rc < 0) {
        err_print("socket PACKET_RX_RING failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    };

    ring->map = mmap(0, ring->mm_len, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_LOCKED | MAP_POPULATE, sock, 0);
    if (ring->map == MAP_FAILED) {
        err_print("mmap failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    }

    ring->rd_len = ring->rd_num * sizeof(*ring->rd);
    ring->rd = malloc_or_die(ring->rd_len);

    for (i = 0; i < ring->rd_num; ++i) {
            ring->rd[i].iov_base = ring->map + (i * ring->flen);
            ring->rd[i].iov_len = ring->flen;
    }    
}

/*
 bind() associates the socket to your network interface thanks to
 sll_ifindex parameter of struct sockaddr_ll.
*/
static void bind_ring(int sock, struct ring *ring, const char *netdev)
{
    int ret;
    debug_print("%s called", __FUNCTION__);

    info_print("bind_ring on '%s' interface", netdev);

    ring->ll.sll_family = PF_PACKET;
    ring->ll.sll_protocol = htons(ETH_P_ALL);
    //ring->ll.sll_ifindex = if_nametoindex(netdev);
    ring->ll.sll_ifindex = 0; // ANY !
    ring->ll.sll_hatype = 0;
    ring->ll.sll_pkttype = 0;
    ring->ll.sll_halen = 0;

    ret = bind(sock, (struct sockaddr *) &ring->ll, sizeof(ring->ll));
    if (ret == -1) {
        err_print("bind failed: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
        
        exit(1);
    }

    // uint32_t fanout_id = getpid() & 0xffff;;
    // uint32_t fanout_arg = (fanout_id | PACKET_FANOUT_FLAG_DEFRAG | (PACKET_FANOUT_HASH << 16));
    // ret = setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
    // if (ret == -1) {
    //     perror("setsockopt");
    //     exit(1);
    // }
}

static int setup_socket(struct ring *ring, const char *netdev)
{
    int sock;
    debug_print("%s called", __FUNCTION__);
    info_print("setuping socket on '%s' interface", netdev);

    sock = setup_pfsocket(TPACKET_V3);

    setup_filter(sock);
    setup_ring(ring);
    mmap_ring(sock, ring);
    bind_ring(sock, ring, netdev);

    return sock;
}

static void rx_packet(struct tpacket3_hdr *ppd)
{
    int rc;

    rc = send_to_zmq(zmq_sock, (void *)ppd, ppd->tp_snaplen, 0);
    if (rc == -1) {
        warn_print("zmq_send failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        return;
    }

    // zmq_msg_t msg;
    // rc = zmq_msg_init_data(&msg, ppd, ppd->tp_snaplen, NULL, NULL);
    // if (rc != 0) {
    //     warn_print("zmq_msg_init_data failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    //     return;
    // }

    // rc = zmq_msg_send (&msg, zmq_sock, 0);
    // if (rc == -1) {
    //     warn_print("zmq_send failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    // }

    return;
}

static
int parse_bpf_filter(char *filter_buffer, u_int caplen, struct bpf_program *filter)
{
    int rc;

    rc = pcap_compile_nopcap(caplen,        /* snaplen_arg */
                            DLT_EN10MB,    /* linktype_arg */
                            filter,        /* program */
                            filter_buffer, /* const char *buf */
                            1,             /* optimize */
                            0              /* mask */
                        );
    if (rc == -1)
        return -1;

    if(filter->bf_insns == NULL)
        return -1;

    // struct bpf_insn *insn = filter.bf_insns;
    // for (int i = 0; i < fcode.bf_len; ++insn, ++i) {
    //   printf("{ 0x%x, %d, %d, 0x%08x },\n", insn->code, insn->jt, insn->jf, insn->k);
    // }

    return 0;
}


static void walk_block(struct block_desc *pbd)
{
    u_int i;
    u_int num_pkts = pbd->h1.num_pkts;
    unsigned long long bytes = 0;
    struct tpacket3_hdr *ppd;

    ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd + pbd->h1.offset_to_first_pkt);

    for (i = 0; i < num_pkts; ++i) {
        bytes += ppd->tp_snaplen;
        rx_packet(ppd);

        ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
        // __sync_synchronize();
    }

    packets_total += num_pkts;
    bytes_total += bytes;
}

static void flush_block(struct block_desc *pbd)
{
    BLOCK_STATUS(pbd) = TP_STATUS_KERNEL;
    __sync_synchronize();
}

static void teardown_ring(struct ring *ring)
{
    debug_print("%s called", __FUNCTION__);

    munmap(ring->map, ring->mm_len);
    debug_print("ring unmapped");

    insane_free(ring->rd);
    debug_print("ring cleared");
}

static void teardown_socket(int sock)
{
    debug_print("%s called", __FUNCTION__);

    close(sock);
    debug_print("sock closed");
}

static void setup_zmq() 
{
    int rc;

    info_print("%s started", __FUNCTION__);

    zmq_sock = zmq_socket (zmq_context, ZMQ_PUB);
    if(zmq_sock == NULL ) {
        err_print("zmq_socket failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_bind (zmq_sock, "inproc://capture");
    if (rc != 0) {
        err_print("zmq_bind _zmq_backend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    zmq_setsockopt_func(zmq_sock);
    zmq_getsockopt_values(zmq_sock);

    info_print("%s completed", __FUNCTION__);
}

extern
void* start_capture(const char *netdev)
{
    int sock, rc;

    struct ring ring;
    struct pollfd pfd;
    unsigned int block_num = 0;
    struct block_desc *pbd;

    // signal(SIGINT, sighandler);
    // signal(SIGQUIT, sighandler);
    // signal(SIGTERM, sighandler);

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

    memset(&ring, 0, sizeof(ring));

    pthread_cleanup_push((void *)teardown_ring, &ring);
    
    sock = setup_socket(&ring, netdev);
    if(sock <= 0) {
        err_print("setup_socket failed ");
        raise(SIGTERM);
        goto error;
    }

    pthread_cleanup_push((void *)teardown_socket, &sock);

    stat_sock = sock;
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
    
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = sock;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;

    setup_zmq();

    pthread_cleanup_push((void *)teardown_zmq_sock, zmq_sock);

    info_print("%s entering main loop", __FUNCTION__);
    
    while(!needQuit(&do_shutdown)) {
        pthread_testcancel();
        pbd = (struct block_desc *) ring.rd[block_num].iov_base;

        while ((BLOCK_STATUS(pbd) & TP_STATUS_USER) == 0) {
            pthread_testcancel();
            rc = poll(&pfd, 1, 1);
            if(rc < 0) {
                warn_print("error while poll events (%d): %s", errno, strerror(errno));
                sleep(1);
            }
        }

        walk_block(pbd);
        flush_block(pbd);
        block_num = (block_num + 1) % NUM_BLOCKS;

        sched_yield();
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_cleanup_pop(3);
    pthread_cleanup_pop(4);

    pthread_exit(0);
}