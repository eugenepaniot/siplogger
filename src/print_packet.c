#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <zmq.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "common.h"
#include "zeromq.h"
#include "print_packet.h"

static void *zmq_sock;

extern
void print_ethernet_header(const unsigned char* buf, int size)
{
    const struct ethhdr *eth = (const struct ethhdr *)buf;

    info_print("Ethernet Header");
    info_print("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    info_print("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    info_print("   |-Protocol            : %u",(unsigned short)eth->h_proto);
    info_print("   |-Pkt Size            : %u", size);
}

extern
void print_ip_header(const unsigned char* buf, int size)
{
    struct sockaddr_in source, dest;
    //unsigned short iphdrlen;

    print_ethernet_header(buf , size);
    
    const struct iphdr *iph = (const struct iphdr *)(buf  + sizeof(struct ethhdr) );
    //iphdrlen = iph->ihl*4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    info_print( "IP Header");
    info_print( "   |-IP Version        : %d",(unsigned int)iph->version);
    info_print( "   |-IP Header Length  : %d DWORDS or %d Bytes",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    info_print( "   |-Type Of Service   : %d",(unsigned int)iph->tos);
    info_print( "   |-Fragment offset   : %d",(unsigned int)iph->frag_off);
    info_print( "   |-IP Total Length   : %d  Bytes(Size of Packet)",ntohs(iph->tot_len));
    info_print( "   |-Identification    : %d",ntohs(iph->id));
    info_print( "   |-TTL      : %d",(unsigned int)iph->ttl);
    info_print( "   |-Protocol : %d",(unsigned int)iph->protocol);
    info_print( "   |-Checksum : %d",ntohs(iph->check));
    info_print( "   |-Source IP        : %s",inet_ntoa(source.sin_addr));
    info_print( "   |-Destination IP   : %s",inet_ntoa(dest.sin_addr));
}

extern
void print_tcp_packet(const unsigned char* buf, int size)
{
    unsigned short iphdrlen;
     
    const struct iphdr *iph = (const struct iphdr *)( buf  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    
    const struct tcphdr *tcph = (const struct tcphdr*)(buf + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    info_print( "***********************TCP Packet*************************");  

    print_ip_header(buf,size);

    info_print( "TCP Header");
    info_print( "   |-Source Port      : %u",ntohs(tcph->source));
    info_print( "   |-Destination Port : %u",ntohs(tcph->dest));
    info_print( "   |-Sequence Number    : %u",ntohl(tcph->seq));
    info_print( "   |-Acknowledge Number : %u",ntohl(tcph->ack_seq));
    info_print( "   |-Header Length      : %d DWORDS or %d BYTES" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    info_print( "   |-CWR Flag : %d",(unsigned int)tcph->cwr);
    info_print( "   |-ECN Flag : %d",(unsigned int)tcph->ece);
    info_print( "   |-Urgent Flag          : %d",(unsigned int)tcph->urg);
    info_print( "   |-Acknowledgement Flag : %d",(unsigned int)tcph->ack);
    info_print( "   |-Push Flag            : %d",(unsigned int)tcph->psh);
    info_print( "   |-Reset Flag           : %d",(unsigned int)tcph->rst);
    info_print( "   |-Synchronise Flag     : %d",(unsigned int)tcph->syn);
    info_print( "   |-Finish Flag          : %d",(unsigned int)tcph->fin);
    info_print( "   |-Window         : %d",ntohs(tcph->window));
    info_print( "   |-Checksum       : %d",ntohs(tcph->check));
    info_print( "   |-Urgent Pointer : %d",tcph->urg_ptr);
    info_print( "                        DATA Dump                         ");

    info_print( "IP RAW Header");
    print_pkt_data(buf,iphdrlen);
    
    info_print( "TCP RAW Header");
    print_pkt_data(buf+iphdrlen,tcph->doff*4);

    info_print( "Data Payload");    
    print_pkt_data(buf + header_size , size - header_size );
    
    info_print( "###########################################################");
}

extern
void print_udp_packet(const unsigned char *buf , int size)
{
    unsigned short iphdrlen;
    
    const struct iphdr *iph = (const struct iphdr *)(buf +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    const struct udphdr *udph = (const struct udphdr*)(buf + iphdrlen  + sizeof(struct ethhdr));
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    info_print( "***********************UDP Packet*************************");
     
    print_ip_header(buf,size);           
     
    info_print( "UDP Header");
    info_print( "   |-Source Port      : %d" , ntohs(udph->source));
    info_print( "   |-Destination Port : %d" , ntohs(udph->dest));
    info_print( "   |-UDP Length       : %d" , ntohs(udph->len));
    info_print( "   |-UDP Checksum     : %d" , ntohs(udph->check));
     
    info_print( "");
    info_print( "IP RAW Header");
    print_pkt_data(buf , iphdrlen);
         
    info_print( "UDP RAW Header");
    print_pkt_data(buf+iphdrlen , sizeof udph);
         
    info_print( "Data Payload");    
     
    //Move the pointer ahead and reduce the size of string
    print_pkt_data(buf + header_size , size - header_size);
     
    info_print( "###########################################################");
}

extern
void print_icmp_packet(const unsigned char* buf , int size)
{
    unsigned short iphdrlen;
     
    const struct iphdr *iph = (const struct iphdr *)(buf  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    
    const struct icmphdr *icmph = (const struct icmphdr *)(buf + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    info_print( "***********************ICMP Packet*************************"); 
     
    print_ip_header(buf , size);
             
    info_print( "");
         
    info_print( "ICMP Header");
    info_print( "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        info_print( "  (TTL Expired)");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        info_print( "  (ICMP Echo Reply)");
    }
     
    info_print( "   |-Code : %d",(unsigned int)(icmph->code));
    info_print( "   |-Checksum : %d",ntohs(icmph->checksum));
    // info_print( "   |-ID       : %d",ntohs(icmph->id));
    // info_print( "   |-Sequence : %d",ntohs(icmph->sequence));
    info_print( "");
 
    info_print( "IP RAW Header");
    print_pkt_data(buf,iphdrlen);
         
    info_print( "UDP RAW Header");
    print_pkt_data(buf + iphdrlen , sizeof icmph);
         
    info_print( "Data Payload");    
     
    //Move the pointer ahead and reduce the size of string
    print_pkt_data(buf + header_size , (size - header_size) );
     
    info_print( "###########################################################");
}

static void print_dash() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    int width = w.ws_col/2;

    fflush(stdout);
    for (int i=0; i<width; i++)
        fprintf(stdout,  "-");

    fprintf(stdout,  "\n");
}

extern
void print_pkt_data (const unsigned char* data , int size)
{
    int i , j;
    setvbuf(stdout, NULL, _IONBF, 0);

    print_dash();

    for(i=0 ; i < size ; i++)
    {
        pthread_testcancel();
        fflush(stdout);
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(stdout,  "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(stdout,  "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(stdout,  "."); //otherwise print a dot
            }
            fprintf(stdout,  "\n");
        }
        
        if(i%16==0) fprintf(stdout,  "   ");

        fprintf(stdout,  " %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
                pthread_testcancel();
                fprintf(stdout,  "   "); //extra spaces
            }
             
            fprintf(stdout,  "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(stdout,  "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(stdout,  ".");
                }
            }
            fprintf(stdout,   "\n" );
        }
    }

    print_dash();
}

extern
void process_packet(const unsigned char* sbuf, int size)
{
    unsigned char* buf = malloc_or_die(size);

    memcpy(buf, sbuf, size);

    const struct iphdr *iph = (const struct iphdr*)(buf + sizeof(struct ethhdr));

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case IPPROTO_ICMP:
            print_icmp_packet( buf , size);
            break;
        
        case IPPROTO_TCP:
            print_tcp_packet(buf , size);
            break;
         
        case IPPROTO_UDP:
            print_udp_packet(buf , size);
            break;
        
        default: //Some Other Protocol like ARP etc.
            print_ethernet_header(buf , size);
            break;
    }

    insane_free(buf);
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
void* start_print_packet() {
    int rc;
    int enable=0;
    
    info_print("%s called", __FUNCTION__);
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

    setup_zmq_sub("inproc://capture");
    pthread_cleanup_push((void *)teardown_zmq_sock, zmq_sock);

    info_print("%s entering main loop", __FUNCTION__);

    while(!needQuit(&do_shutdown) && enable==1) {
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

        struct tpacket3_hdr *ppd = (struct tpacket3_hdr *) zmq_msg_data(&msg);
        u_char* pkt = (u_char *)((uint8_t *) ppd + ppd->tp_mac);
        process_packet(pkt, ppd->tp_snaplen);

free_msg:
        zmq_msg_close(&msg);
    }
    
error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);

    pthread_exit(0);
}