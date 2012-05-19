#ifndef _MAIN_H_
#define _MAIN_H_

#include "log.h"
#include "pairing_heap.h"

extern heap* g_pheap;
extern Logger g_errlog, g_accesslog;

#define logerr(...) logfl(g_errlog, __VA_ARGS__)
#define logNreturn(...) {logerr(__VA_ARGS__); return -1;}

#define log_listen_fd_errors(ev_int) if (ev_int & EPOLLERR)\
        								logerr("EPOLLERR on listen_fd");\
    								 if (ev_int & EPOLLHUP)\
        								logerr("EPOLLHUP on listen_fd");\
   									 if (ev_int & EPOLLRDHUP)\
       									 logerr("EPOLLRDHUP on listen_fd");

#define logNclose_conn(pheap_n, fmt, ...) {\
    logerr("fd%d " fmt, pheap_n->value.fd, __VA_ARGS__);\
	close_conn(pheap_n)}

#define close_conn(pheap_n) {\
	if (close(pheap_n->value.fd) == -1)\
        logerr("close fd%d error: %s", pheap_n->value.fd, strerror(errno));\
    heap_decrease_key(g_pheap, pheap_n, 2);\
    heap_delete_min(g_pheap);}

#define change_state2http_recv_init {pconn->state = HTTP_RECV_INIT;\
									pconn->preq_buf = pconn->req_buf;\
									*pconn->req_buf = 0;\
									pconn->content_length = -1;\
									pconn->static_content_fd = -1;}

#define chage_state2http_recv_header {\
                if (*(pconn->p_newline - 1) == '\r')\
                    pconn->p_end_of_init = pconn->p_newline - 1;\
                else\
                    pconn->p_end_of_init = pconn->p_newline;\
                pconn->state = HTTP_RECV_HEADER;\
                pconn->content_length = -1;\
                goto http_recv_header;}

// err = 0, client shutdown **orign goto do_action;
// 413, reqeust entity too long
// 4444 '\0' char in request
#define handle_recv_errors(err) if (!err) {\
							if (close(pconn->fd) == -1)\
        						logerr("close fd%d error: %s", pconn->fd, strerror(errno));\
    						heap_decrease_key(g_pheap, pconn->pheap_node, 2);\
    						heap_delete_min(g_pheap);\
							return;}\
						if (err == -413) {\
							pconn->http_resp_code = 413;\
							goto prepare_http_send_resp;\
						}\
						if (err == -4444) {\
							pconn->http_resp_code = 400;\
							strcpy(pconn->resp_buf, "'\\0' char in request");\
							pconn->resp_content_length = 20;\
							goto prepare_http_send_resp;\
						}

#endif
