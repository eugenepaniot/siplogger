extern int zmq_linger_time;
extern int zmq_hwm_msg;
extern int zmq_sndtimeo;
extern void *zmq_context;

extern unsigned long long zmq_send_msq_total, zmq_send_msq_total_failed, zmq_send_bytes_total;

extern void zmq_ctx_destroy_func(void *zmq_ctx);
extern void zmq_getsockopt_values(void *zmq_sock);
extern void zmq_setsockopt_func(void *zmq_sock);

extern void teardown_zmq_sock(void *zmq_sock);

extern void zqm_wait_for_context();

extern 
int send_to_zmq(void *zmq_sock, void * data, u_int len, int flags) ;

extern void start_zeromq();
