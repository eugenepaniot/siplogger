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
#include <ifaddrs.h>

// #include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_const.h>
#include <osipparser2/osip_headers.h>
#include <osipparser2/osip_body.h>
#include <osipparser2/osip_list.h>

#include "common.h"
#include "zeromq.h"
#include "siplogger.h"

static void *zmq_sock;
static char *empty = "-";

struct cap_packet {
    char tstamp[64];
    char src_ip[16];
    char dst_ip[16];
    const char* payload;
    char direction;
};

static struct macs_str {
    char ** macs;
    size_t size;
} mymacs;

/*
NVITE sip:+442033180208@10.62.5.168:5060 SIP/2.0
Via: SIP/2.0/UDP 10.62.1.30:5070;rport;branch=z9hG4bKPj4b5bfffa64b346f0a35cbf6ad1154a1c
Max-Forwards: 70
User-Agent: RC_SIPWRP_1.30
From: "RINGCENTRAL   D" <sip:+16502830004@10.62.1.30>;tag=10.62.1.30-5070-08f70fc9ed3f47d8
To: "RINGCENTRAL   D" <sip:+442033180208@10.62.5.168>
Contact: <sip:+16502830004@10.62.1.30:5070;transport=udp>
Call-ID: 8b279901428541518db6131720e9a77d
CSeq: 18782 INVITE
p-rc-session-id: 36be2c14-866386d1-29d7fbd6@192.168.73.101
P-RC-Media-Location: ars01
p-rc-account-info: usr:400129302004;mbx:400178112004
Call-Info: <36be2c14-866386d1-29d7fbd6@192.168.73.101>;purpose=info
Allow: SUBSCRIBE, NOTIFY, REFER, INVITE, ACK, BYE, CANCEL, UPDATE, INFO
Supported: replaces, timer, diversion
Session-Expires: 3600;refresher=uac
Min-SE: 90
Content-Type: application/sdp
Content-Length:   510

v=0
o=- 3481015106 804000756 IN IP4 10.62.26.209
s=SmcSip
c=IN IP4 10.62.26.209
t=0 0
m=audio 24450 RTP/AVP 0 9 18 96 8 109 111 101
a=rtpmap:0 pcmu/8000
a=rtpmap:9 g722/8000
a=rtpmap:18 g729/8000
a=fmtp:18 annexb=no
a=rtpmap:96 ilbc/8000
a=fmtp:96 mode=20
a=rtpmap:8 pcma/8000
a=rtpmap:109 OPUS/16000
a=fmtp:109 useinbandfec=1
a=rtcp-fb:109 ccm tmmbr
a=rtpmap:111 OPUS/48000/2
a=fmtp:111 useinbandfec=1
a=rtcp-fb:111 ccm tmmbr
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv


REGISTER sip:10.15.142.25:5060 SIP/2.0
Record-Route: <sip:10.15.20.224;lr;ftag=7b4e9e10>
Via: SIP/2.0/UDP 10.15.20.224;branch=z9hG4bK60c4.c0f0f1b6.0
Via: SIP/2.0/UDP 192.168.51.203:51001;branch=z9hG4bK-d8754z-f808193845110778-1---d8754z-;rport=51001
Max-Forwards: 69
Contact: <sip:15123771836@192.168.51.203:51001;rinstance=8cb49a7bc64359be>
To: "polina.sharykhina"<sip:15123771836@sip.stage.ringcentral.com:5060>
From: "polina.sharykhina"<sip:15123771836@sip.stage.ringcentral.com:5060>;tag=7b4e9e10
Call-ID: MTY4NjVlYjliNjY4N2Y0YmVjZGIwYWM3MjFlYzE3ZjE.
CSeq: 1901 REGISTER
Expires: 120
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY, REFER, INFO, MESSAGE
Supported: replaces
User-Agent: 3CXPhone 6.0.26523.0
Authorization: Digest username="86239321008",realm="sip.stage.ringcentral.com",nonce="WOa8e1jmu0//RGdun27zPL0EkZBe6ZiV",uri="sip:sip.stage.ringcentral.com:5060",response="56e60aa3537b1269b31ab139618746a2",algorithm=MD5
Content-Length: 0
Supported: path



*/

// https://fossies.org/linux/libosip2/src/test/torture.c
// ftp://ftp.tu-clausthal.de/pub/mirror/gnu/www/software/osip/doc/osip-0.7.x.html
// ftp://ftp.oreilly.co.jp/apache2/unpacked/apache_1.3.9/src/modules/standard/mod_log_config.c

/*
struct sip_packet {
    int type;

    char *method;
    char *uri;
    char *rr;
    char *rs;

    char *from_num;
    char *from_host;
    char *from_tag;

    char *to_num;
    char *to_host;
    char *to_tag;

    char *cid;
    char *cseq;
    char *session;
    char *ua;
    char *auth;
    char *media;
    char *event;
    char *src;
    char *local_ip;
    
    char *raw_contact;
    char contact[256];
    char expires[256];

    char via[256];
    char codecs[256];
};

    printf("Log field definitions:\n");
    printf("URI  : SIP Uniform Resource Identifier\n");
    printf("RR   : Reply reason\n");
    printf("RS   : Reply status code\n");
    printf("F    : 'From' header, format 'from_number@ip_address'\n");
    printf("FT   : 'From' header, 'tag' parameter\n");
    printf("T    : 'To' field, format 'to_number@ip_address'\n");
    printf("TT   : 'To' header, 'tag' parameter\n");
    printf("C    : 'Call-ID' header\n");
    printf("CS   : 'CSeq' header, sequence number only\n");
    printf("PS   : 'p-rc-session-id' header, Ringcentral session identifier\n");
    printf("UA   : 'User-Agent' header\n");
    printf("AU   : 'Proxy-Authorization' or 'Authorization' header\n");
    printf("VIA  : 'Via' header, list of IP addresses\n");
    printf("M    : 'm' header, SDP media type\n");
    printf("MC   : 'a=rtpmap' headers, SDP codec list\n");
    printf("E    : 'Event' header, applicable for NOTIFY requests\n");
    printf("SRC  : Source IP address of the client taken from 'P-RC-Source-IP' header\n");
    printf("CON  : Latest value of Contact header\n");
    printf("EXP  : Expires value for the latest Contact header value\n");
    printf("LIP  : Local IP address of the client taken from 'P-RC-Local-IP' header\n");

    if (sip.type == SIP_REQUEST) {
        snprintf(message, sizeof(message), "{ \"MSG_TIME\": \"%s\", \"DIRECTION\": \"%c\", \"SRC_IP\": \"%s\", \"DST_IP\": \"%s\", 
        \"MSG_TYPE\": \"REQ\", 
        \"SIP_METHOD\": \"%s\", 
        \"SIP_URI\": \"%s\", \"SIP_CALL_ID\": \"%s\", \"SIP_CSEQ\": \"%s\", 
        \"SIP_FROM\": \"%s@%s\", \"SIP_FROM_TAG\": \"%s\", 
        \"SIP_TO\": \"%s@%s\", \"SIP_TO_TAG\": \"%s\", \"SIP_AUTH\": \"%s\", \"SIP_RC_SESSION_ID\": \"%s\", \"SIP_VIA\": \"%s\", \"SIP_MEDIA_TYPE\": \"%s\", \"SIP_MEDIA_CODEC\": \"%s\", \"SIP_EVENT\": \"%s\", \"SIP_UA\": \"%s\", \"SIP_RC_SRC_IP\": \"%s\", \"SIP_CONTACT\": \"%s\", \"SIP_RC_LOCAL_IP\": \"%s\" }\n", 
        packet.tstamp, packet.direction, packet.src_ip, packet.dst_ip, 
        sip.method, sip.uri, sip.cid, sip.cseq, sip.from_num, sip.from_host, sip.from_tag, sip.to_num, sip.to_host, sip.to_tag, sip.auth, sip.session, sip.via, 
        sip.media, sip.codecs, sip.event, sip.ua, sip.src, sip.contact, sip.local_ip);

    } else {
        snprintf(message, sizeof(message), "{ \"MSG_TIME\": \"%s\", \"DIRECTION\": \"%c\", \"SRC_IP\": \"%s\", \"DST_IP\": \"%s\", 
        \"MSG_TYPE\": \"RESP\", 
        \"SIP_METHOD\": \"%s\", 
        \"SIP_RESP_CODE\": \"%s\", \"SIP_RESP_PHRASE\": \"%s\", \"SIP_CALL_ID\": \"%s\", \"SIP_CSEQ\": \"%s\", \"SIP_FROM\": \"%s@%s\", \"SIP_FROM_TAG\": \"%s\", \"SIP_TO\": \"%s@%s\", \"SIP_TO_TAG\": \"%s\", \"SIP_AUTH\": \"%s\", \"SIP_RC_SESSION_ID\": \"%s\", \"SIP_VIA\": \"%s\", \"SIP_MEDIA_TYPE\": \"%s\", \"SIP_MEDIA_CODEC\": \"%s\", \"SIP_EVENT\": \"%s\", \"SIP_UA\": \"%s\", \"SIP_CONTACT\": \"%s\", \"SIP_CONTACT_EXPIRE\": \"%s\" }\n", 
        packet.tstamp, packet.direction, packet.src_ip, packet.dst_ip, 
        sip.method, sip.rs, sip.rr, sip.cid, sip.cseq, sip.from_num, sip.from_host, sip.from_tag, sip.to_num, sip.to_host, sip.to_tag, sip.auth, sip.session, sip.via, 
        sip.media, sip.codecs, sip.event, sip.ua, sip.contact, sip.expires);
    }


{ "MSG_TIME": "1493222742517", "DIRECTION": "I", "SRC_IP": "10.24.142.11", "DST_IP": "10.24.142.13", "MSG_TYPE": "REQ", "SIP_METHOD": "REGISTER", 
"SIP_URI": "sip:sip.ops.ringcentral.com:5060", "SIP_CALL_ID": "1053003941@10.24.142.11", "SIP_CSEQ": "2", "SIP_FROM": "16502578396@sip.ops.ringcentral.com", 
"SIP_FROM_TAG": "3ec390a5", "SIP_TO": "16502578396@sip.ops.ringcentral.com", "SIP_TO_TAG": "-", "SIP_AUTH": "1910594004", "SIP_RC_SESSION_ID": "-", "SIP_VIA": "10.24.142.11", 
"SIP_MEDIA_TYPE": "-", "SIP_MEDIA_CODEC": "-", "SIP_EVENT": "-", "SIP_UA": "sipsak 0.9.6", "SIP_RC_SRC_IP": "-", "SIP_CONTACT": "sip:16502578396@10.24.142.11:44853", 
"SIP_RC_LOCAL_IP": "-" }

{ "MSG_TIME": "1493222742517", "DIRECTION": "O", "SRC_IP": "10.24.142.13", "DST_IP": "10.24.142.11", "MSG_TYPE": "RESP", "SIP_METHOD": "REGISTER", "SIP_RESP_CODE": "100", 
"SIP_RESP_PHRASE": "Giving a try", "SIP_CALL_ID": "1053003941@10.24.142.11", "SIP_CSEQ": "2", "SIP_FROM": "16502578396@sip.ops.ringcentral.com", "SIP_FROM_TAG": "3ec390a5", 
"SIP_TO": "16502578396@sip.ops.ringcentral.com", "SIP_TO_TAG": "-", "SIP_AUTH": "-", "SIP_RC_SESSION_ID": "-", "SIP_VIA": "10.24.142.11", "SIP_MEDIA_TYPE": "-", 
"SIP_MEDIA_CODEC": "-", "SIP_EVENT": "-", "SIP_UA": "-", "SIP_CONTACT": "-", "SIP_CONTACT_EXPIRE": "-" }

*/

static void parse_sip (const struct cap_packet * cp, size_t len) {
    int rc;

    osip_message_t *sip;
    //char* payload = malloc_or_die(sizeof(char) * len);
    //memcpy(payload, cp->payload, len);

    char message[1024];

    char *url = empty, *callid = empty, cseq[128], from[256], from_tag[256],
    to[256], to_tag[256], sip_auth[256];
    osip_uri_param_t *tag_param;

    rc = osip_message_init(&sip);
    if (rc != 0) {
        err_print("osip_message_init failed"); 
        goto error;
    }

    // debug_print("cp->payload: %s", cp->payload);

    rc = osip_message_parse(sip, cp->payload, strlen(cp->payload));
    if (rc < 0) {
        warn_print("osip_message_parse failed %d. Payload: '%s'", rc, cp->payload);
        goto error;
    }

    if (MSG_IS_REQUEST(sip)) {
        // debug_print("sip_method: %s", sip->sip_method);

        if(osip_uri_to_str(osip_message_get_uri(sip), &url) < 0)
            warn_print("osip_uri_to_str failed");

        if(osip_call_id_to_str(osip_message_get_call_id(sip), &callid) < 0)
            warn_print("osip_call_id_to_str failed");

        snprintf(cseq, 128, osip_cseq_get_number(osip_message_get_cseq(sip)), 1);
        if(cseq == NULL) {
            warn_print("osip_cseq_to_str failed");
            strncpy(cseq, empty, 1);
        }

        snprintf(from, 128, "%s@%s", osip_from_get_url(osip_message_get_from(sip))->username, osip_from_get_url(osip_message_get_from(sip))->host);
        if( from == NULL) {
            warn_print("SIP from failed");
            strncpy(from, empty, 1);
        }

        rc = osip_from_get_tag(osip_message_get_from(sip), &tag_param);
        if( rc != 0 || tag_param->gvalue == NULL) {
            warn_print("SIP from tag failed");
            strncpy(from_tag, empty, 1);
        } else {
            strncpy(from_tag, tag_param->gvalue, 256);
        }

        snprintf(to, 128, "%s@%s", osip_to_get_url(osip_message_get_to(sip))->username, osip_to_get_url(osip_message_get_to(sip))->host);
        if( to == NULL) {
            warn_print("SIP from failed");
            strncpy(to, empty, 1);
        }

        rc = osip_from_get_tag(osip_message_get_from(sip), &tag_param);
        if( rc != 0 || tag_param->gvalue == NULL) {
            warn_print("SIP from tag failed");
            strncpy(to_tag, empty, 1);
        } else {
            strncpy(to_tag, tag_param->gvalue, 256);
        }

         // osip_message_get_proxy_authorization (const osip_message_t * sip, int pos, osip_proxy_authorization_t ** dest)

        osip_proxy_authenticate_t *osip_proxy_auth;
        rc = osip_message_get_proxy_authenticate(sip, 0, &osip_proxy_auth);
        if (rc != 0) {
            //warn_print("osip_message_get_proxy_authorization failed");
            strncpy(sip_auth, empty, 1);
        } else {
            strncpy(sip_auth, osip_proxy_auth->realm, 256);
        }

        // p-rc-routing-key

        if(strncmp(sip_auth, "-", 1) != 0)
        {

        snprintf(message, sizeof(message), "{"
            "\"MSG_TIME\": \"%s\", \"DIRECTION\": \"%c\", \"SRC_IP\": \"%s\", \"DST_IP\": \"%s\", "
            "\"MSG_TYPE\": \"REQ\", "
            "\"SIP_METHOD\": \"%s\", "
            "\"SIP_URI\": \"%s\", "
            "\"SIP_CALL_ID\": \"%s\", "
            "\"SIP_CSEQ\": \"%s\", "
            "\"SIP_FROM\": \"%s\", "
            "\"SIP_FROM_TAG\": \"%s\", "
            "\"SIP_TO\": \"%s\", "
            "\"SIP_TO_TAG\": \"%s\", "
            "\"SIP_AUTH\": \"%s\", "
        "}",
            cp->tstamp, cp->direction, cp->src_ip, cp->dst_ip,
            sip->sip_method,
            url, callid, cseq, from, from_tag, 
            to, to_tag, sip_auth

        );

        info_print("%s", message);

        }
    }
    else if MSG_IS_RESPONSE(sip) {
        // debug_print("status_code: %d", sip->status_code);
    }
    else {
        warn_print("Unknown message. Payload: %s", cp->payload);
    }

error:
    // insane_free(payload);
    // osip_free(url);
    // osip_free(callid);
    // osip_free(tag_param);
    // insane_free(tag);

    osip_message_free(sip);
    //sdp_message_free(sdp);

    return;
}

static void propagate_if_addrs() {
    int rc;

    struct ifaddrs *ifa, *ifaddr;

    debug_print("%s called", __FUNCTION__);

    rc = getifaddrs(&ifaddr);
    if (rc == -1) {
        err_print("getifaddrs: (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
    }

    mymacs.macs = (char **) malloc(sizeof(char *));

    ifa = ifaddr;
    for (int n = 0, i = 0; ifa != NULL ; ifa = ifa->ifa_next, mymacs.size = i, n++) {
        if(ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET)
            continue;

        struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
        char mac[19];

        for(int j = 0, len = 0; j < 6; j++)
            len += sprintf(mac+len, "%02X%s", s->sll_addr[j], j < 5 ? ":":"");

        mymacs.macs[i] = malloc_or_die(strlen(mac));
        strncpy(mymacs.macs[i], mac, strlen(mac));

        debug_print("Found device with mac: %s", mac);
        i++;
    }
    info_print("%s completed", __FUNCTION__);
}

static int is_my_mac(char * mac) 
{
    for(u_int i = 0; i < mymacs.size; i++) {
        if(strncmp(mymacs.macs[i], mac, strlen(mymacs.macs[i])) == 0)
            return 1;
    }

    return 0;
}

static void teardown_if_addrs() {
    debug_print("%s called", __FUNCTION__);

    for(u_int i = 0; i < mymacs.size; i++)
        insane_free(mymacs.macs[i]);

    insane_free(mymacs.macs);

    info_print("%s completed", __FUNCTION__);
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
void* start_parser() {
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

    propagate_if_addrs();

    pthread_cleanup_push((void *)teardown_if_addrs, NULL);

    zqm_wait_for_context(zmq_context);

    setup_zmq_sub("inproc://capture");
    pthread_cleanup_push((void *)teardown_zmq_sock, zmq_sock);

    parser_init();

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

        const struct tpacket3_hdr *ppd = (const struct tpacket3_hdr *) zmq_msg_data(&msg);
        const int size = ppd->tp_snaplen;
        const u_char* pkt = (const u_char *)((const uint8_t *) ppd + ppd->tp_mac);

        const struct iphdr *iph = (const struct iphdr *)(pkt +  sizeof(struct ethhdr));
        const u_short iphdrlen = iph->ihl*4;
        int header_size = sizeof(struct ethhdr) + iphdrlen;

        const struct tcphdr *tcph;
        const struct udphdr *udph;

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                tcph = (const struct tcphdr*)(pkt + iphdrlen + sizeof(struct ethhdr));
                header_size += tcph->doff*4;

                break;
             
            case IPPROTO_UDP:
                udph = (const struct udphdr*)(pkt + iphdrlen  + sizeof(struct ethhdr));
                header_size += sizeof(udph);

                break;
            
            default:
                warn_print("unknown protocol: %d", iph->protocol);
                goto free_msg;
        }

        struct cap_packet *cp = malloc(sizeof(struct cap_packet));

        cp->payload = (const char *)(pkt + header_size);

        //memcpy(cp->payload, (const char *)(pkt + header_size), size-header_size );
        
        char mac[19];
        for(int i = 0, len = 0; i < 6; i++)
            len += sprintf(mac+len, "%02X%s", ((const struct ethhdr *)pkt)->h_dest[i], i < 5 ? ":":"");

        if (is_my_mac(mac)) {
            cp->direction = 'I';
        } else {
            cp->direction = 'O';
        }

        snprintf(cp->src_ip, 16, "%s", inet_ntoa(*(const struct in_addr *)&iph->saddr));
        snprintf(cp->dst_ip, 16, "%s", inet_ntoa(*(const struct in_addr *)&iph->daddr));
        snprintf(cp->tstamp, 64, "%llu", (long long unsigned int)(ppd->tp_sec)*1000 + (ppd->tp_nsec / 1000 ) / 1000);

        parse_sip(cp, size-header_size);

        // insane_free(cp);
free_msg:
        zmq_msg_close(&msg);
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_cleanup_pop(3);

    pthread_exit(0);
}