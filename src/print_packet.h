extern void print_ethernet_header(const unsigned char* buf, int size);
extern void print_ip_header(const unsigned char* buf, int size);
extern void print_tcp_packet(const unsigned char* buf, int size);
extern void print_udp_packet(const unsigned char *buf , int size);
extern void print_icmp_packet(const unsigned char* buf , int size);
extern void print_pkt_data (const unsigned char* data , int size);
extern void process_packet(const unsigned char* buf, int size);

extern void* start_print_packet();