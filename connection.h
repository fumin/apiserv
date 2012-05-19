#ifndef _CONNECTION_H_
#define _CONNECTION_H_
#include <sys/uio.h>
#include <sys/socket.h>
#include <time.h>

#define CONN_REQ_BUF_LEN 512
#define CONN_RESP_HEADER_LEN 256
#define CONN_RESP_BUF_LEN 1024

#define HTTP_RECV_INIT 0
#define HTTP_RECV_HEADER 1
#define HTTP_RECV_BODY 2
#define DO_ACTION 3
#define HTTP_SEND_RESP 4

typedef struct heap_node heap_node;
typedef struct heap heap;

struct conn_writev_t {
	// iovs[0] for http response header
	// iovs[1] for http response body
    struct iovec iovs[2];
    struct iovec* iov;
    int iovcnt;
};

struct connection_t {
    int state; // http request processing state
    int fd; // socket fd
    struct sockaddr client_addr;
    unsigned int events; // the events set for socket fd
    time_t timeout; // absolute timeout time
    heap_node* pheap_node; 

    char req_buf[CONN_REQ_BUF_LEN];
    char* preq_buf; // marks the end of req_buf's used portion

    int content_length; // request header
    char* p_newline; // auxiliary variable for parsing headers
	char* p_end_of_init;

    int http_resp_code;
    char resp_header_buf[CONN_RESP_HEADER_LEN];
    int resp_header_len;
    char resp_buf[CONN_RESP_BUF_LEN];
    off_t resp_content_length; // can be either file size for static content
							 // or the response size for dynamic content
    off_t resp_header_write_offset; // mark the portion that is yet to be sent
    off_t resp_body_write_offset; // mark the portion that is yet to be sent

    int static_content_fd;

    struct conn_writev_t writev_s; // variable used internally by writev_ex() 

    unsigned int tcp_cork:1;
};

#endif
