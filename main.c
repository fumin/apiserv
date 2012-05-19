// .conf file
//SIGHUP reread .conf
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "main.h"
#include "fd_cache.h"

static int determine_epoll_wait_timeout(void);
static void drop_timeouted_conns(void);
static void http_coroutine(struct connection_t*, unsigned int);
static void log_http_access(struct connection_t*);
static int sendfile_ex(struct connection_t*);
static void setTCP_CORK(struct connection_t*, int);
static int write_header(struct connection_t*);
static int writev_ex(struct connection_t*);
static void adjust_iov(struct conn_writev_t*, int);
static int total_length_of_iov(struct conn_writev_t*);
static int change_state2http_send_resp(struct connection_t*);
static char* http_code2str(int);
static void modify_to_EPOLLOUT(struct connection_t*);
static void handle_http_get_request(struct connection_t*);
static int get_http_headers(struct connection_t*);
static char* recv_ex(struct connection_t*, int*);
static int prepare_resp_bufs(struct connection_t*);
static void handle_err_event(struct epoll_event*);
static void accept_listen_fd(int, struct epoll_event*);
static int socket_bind_listen (const char port[]);
int setnonblocking(int);
void daemonize(const char *, const char[]);
void pr_exit(pid_t, int);
int lockfile(int);
int already_running(const char[]);

Logger g_errlog, g_accesslog;
heap* g_pheap;

static int epfd;
static struct epoll_event ev;
static FDcache fd_cache;
static time_t fd_cache_time;
static time_t g_timeout_interval;

static volatile sig_atomic_t srv_shutdown = 0;
static volatile sig_atomic_t handle_sig_hup = 0;
static volatile sig_atomic_t forwarded_sig_hup = 0;
static volatile sig_atomic_t handle_sig_usr1 = 0;
static volatile sig_atomic_t forwarded_sig_usr1 = 0;
static volatile siginfo_t last_sigterm_info;
static volatile siginfo_t last_sighup_info;
static volatile siginfo_t last_sigusr1_info;
static void sigaction_handler(int sig, siginfo_t* si, void* context) {
	static siginfo_t empty_siginfo;
//	UNUSED(context);
	if (!si) si = &empty_siginfo;
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		srv_shutdown = 1;
		last_sigterm_info = *si;
		break;
	case SIGHUP:
		if (!forwarded_sig_hup) {
			handle_sig_hup = 1;
			last_sighup_info = *si;
		} else {
			forwarded_sig_hup = 0;
		}
		break;
	case SIGUSR1:
		if (!forwarded_sig_usr1) {
            handle_sig_usr1 = 1;
            last_sigusr1_info = *si;
        } else {
            forwarded_sig_usr1 = 0;
        }
        break;
	}
}

int main(int argc, char* argv[]) {
	int listen_fd, num_childs_to_be_created = 4, is_child, 
		wait_status, child_pid, events_len = 512, num_got_events,
		i, epoll_wait_timeout, testint;
	struct sigaction act;
	struct epoll_event events[512];
	heap* pheap;
	struct connection_t* pconn;

	char WEB_HOME_DIR[] = "/home/fumin/myserver/www";
	g_timeout_interval = 75;

	daemonize("apiserv", "/home/fumin/myserver/apiserv.error.log");

	if ((g_accesslog =
        newLogger2("/home/fumin/myserver/apiserv.access.log", 
		g_errlog)) == NULL)
        logNreturn("can't open access log")
	if (already_running("/home/fumin/myserver/apiserv.pid")) 
		logNreturn("server is already running")
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) < 0) 
		logNreturn("sigaction SIGPIPE error: %s", strerror(errno))
	act.sa_sigaction = sigaction_handler;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGHUP, &act, NULL) < 0 ||
		sigaction(SIGUSR1, &act, NULL) < 0 ||
		sigaction(SIGTERM, &act, NULL) < 0 ||
		sigaction(SIGINT, &act, NULL) < 0) 
		logNreturn("sigaction error: %s", strerror(errno))
	if ((listen_fd = socket_bind_listen("3389")) == -1) logNreturn("sbl error")

	num_childs_to_be_created = 2; is_child = 0;
	if (num_childs_to_be_created > 0) {
		while (!is_child) {
			if (num_childs_to_be_created > 0) {
				switch (child_pid = fork()) {
				case -1:
					logerr("fork error: %s", strerror(errno));
					break;
				case 0:
					is_child = 1; // we leave the while(!is_child) loop as
								  // a child worker process
					break;
				default:
					logerr("[INFO] worker created with pid: %d", child_pid);
					--num_childs_to_be_created;
				}
			} else {
				// we are the parent, and we wait here for 
				// our children after they have all been created
				if ((child_pid = wait(&wait_status)) != -1) { 
					pr_exit(child_pid, wait_status);
					// one of our workers went away, recreate it in 
					// the next while(!is_child) loop
					++num_childs_to_be_created;
				} else {
					// we, as the parent, received a signal interrupt
					if (errno == EINTR) {
						if (handle_sig_hup) {
							handle_sig_hup = 0;
							// TO DO reread configutation
							if (!forwarded_sig_hup) {
								// send SIGHUP to all processes in this
								// process group (which includes 
								// the parent itself). For this reason,
								// we turn on the forwarded_sig_hup guard
								// to prevent an infinite SIGHUP loop
								forwarded_sig_hup = 1;
								kill(0, SIGHUP);
							}
						} else if (handle_sig_usr1) {
							handle_sig_usr1 = 0;
							if (!forwarded_sig_usr1) {
								forwarded_sig_usr1 = 1;
								kill(0, SIGUSR1);
							}
						} else if (srv_shutdown) 
							break;
						else 
							continue;
					} else /*if (errno == ECHILD)*/ {
						logerr("main.wait error: %s", strerror(errno));
						exit(1);
					}
				}
			}
		} // while(!is_child)

		// this is the exit-point for the parent
		if (!is_child) {
			// kill all children too
			if (srv_shutdown) {
				logerr("server shutdown, SIGTERM or SIGINT sent by"
                	" UID = %d, PID = %ld",
                    last_sigterm_info.si_uid, last_sigterm_info.si_pid);
				kill(0, SIGTERM);
			}
			deleteLogger(g_accesslog);
			deleteLogger(g_errlog);
			exit(0);
		}
	} else { // num_childs_to_be_created < 0
		logerr("num_childs_to_be_created < 0");
		exit(1);
	}
	
	// we are the child worker now
	g_logpid = getpid();
	fd_cache = newFDcache(WEB_HOME_DIR, g_errlog);
	g_pheap = heap_new();
	fd_cache_time = 10;
	// the size field of epoll_create is ignored since 2.6.8
	if ((epfd = epoll_create(250000)) == -1) 
		logNreturn("epoll_create error: %s", strerror(errno))
	ev.data.fd = listen_fd;
	ev.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) == -1)
		logNreturn("epoll_ctl error: %s", strerror(errno))
	while (1) {
		// clear open file descriptors cache every 60 secs
		if (*gp_current_timestamp - fd_cache_time > 60) {
			clear_fd_cache(fd_cache);
			fd_cache_time = *gp_current_timestamp;
		}
		if (srv_shutdown) exit(0);
		if (handle_sig_usr1) {
        	handle_sig_usr1 = 0;
            logerr("cycling access logs, signal sent by UID = %d, PID = %ld",
            	last_sigusr1_info.si_uid, last_sigusr1_info.si_pid);
            reopen_logfile(g_accesslog, g_errlog);
        }
testint = determine_epoll_wait_timeout();
//logerr("testint = %d",testint);
		if ((num_got_events = epoll_wait(epfd, events, events_len, 
				/*determine_epoll_wait_timeout()*/testint)) == -1) {
//logerr("epoll_wait error on EINTR %s", strerror(errno));
			if (errno == EINTR) continue;
			else logNreturn("epoll_wait error: %s", strerror(errno))
		}
//logerr("go num of epoll events %d", num_got_events);
		for (i = 0; i < num_got_events; ++i) {
			if (events[i].data.fd == listen_fd) {
//logerr("we are listen fd");
				accept_listen_fd(listen_fd, &events[i]);}
			else {
				if (events[i].events & (EPOLLERR|EPOLLHUP|EPOLLRDHUP)) {
//logerr("EPOLLERR|EPOLLHUP|EPOLLRDHU");
					handle_err_event(&events[i]);
					continue; // continue with the next event upon error
				}
//logerr("coroutine..");
				http_coroutine(events[i].data.ptr, events[i].events);
			}
		}
	} // while(1) main loop
}

static int determine_epoll_wait_timeout(void) {
	struct connection_t* pconn;
	int epoll_wait_timeout;
	if ((pconn = heap_min(g_pheap)) != NULL) {
		// the equal sign in "<= 0" is very important!
		// if not, we'll be crazily looping for 1 whole sec
//logerr("inside det %d", g_heap_num_ele);
    	if ((epoll_wait_timeout =
        		1000 * (pconn->timeout - *gp_current_timestamp)) <= 0) {
       		drop_timeouted_conns();
//logerr("after det wait %d", g_heap_num_ele);
			if (heap_min(g_pheap) == NULL) return -1;
            else return 0;
        } else
			return epoll_wait_timeout;
    } else 
		return -1;
}

static void drop_timeouted_conns(void) {
	static char resp[] = "HTTP/1.1 408 Request Timeout\r\n"
						 "Server: fumin/0.1\r\n\r\n";
	struct connection_t* pconn;
	while (1) {
		pconn = heap_min(g_pheap);
		if (pconn == NULL || pconn->timeout > *gp_current_timestamp) return; 
		pconn->http_resp_code = 408;
		write(pconn->fd, resp, sizeof(resp));
		log_http_access(pconn);
		close_conn(pconn->pheap_node)
	}
}

static void http_coroutine(struct connection_t* pconn, unsigned int events) {
	int err;
	char* pc, *p_next_newline; // pc is the previous position of '\0'
	switch (pconn->state) {
	case HTTP_RECV_INIT:
		http_recv_init:
		if (!(events & EPOLLIN)) return;
//logerr("recved! init");
		while (1) {
			if ((pc = recv_ex(pconn, &err)) == NULL) return;
			handle_recv_errors(err)
			if ((pconn->p_newline = strchr(pc, '\n')) != NULL) 
				chage_state2http_recv_header
		}
//	case HTTP_RECV_HEADER:
		http_recv_header:
//		if (!(events & EPOLLIN)) return;
//logerr("recv header...");
//logerr("%s == %c", pconn->req_buf, *pconn->p_newline);
		while (1) {
			if (get_http_headers(pconn)) {
                if (pconn->content_length > 0) {pconn->state = HTTP_RECV_BODY;goto http_recv_body;}
                else goto do_action;
            }
//logerr("get_http_headers() returns 1");
//sleep(1);
// perhaps case HTTP_RECV_HEADER should be put here
			case HTTP_RECV_HEADER:
			if (!(events & EPOLLIN)) return;
			if ((pc = recv_ex(pconn, &err)) == NULL) return;
			handle_recv_errors(err)
		}
//	case HTTP_RECV_BODY:
		http_recv_body:
//		if (!(events & EPOLLIN)) return;
//logerr("recv body.");
		while (1) {
			if (strlen(pconn->p_newline) >= pconn->content_length)
                goto do_action;
			case HTTP_RECV_BODY:
			if (!(events & EPOLLIN)) return;
			if ((pc = recv_ex(pconn, &err)) == NULL) return;
			handle_recv_errors(err)
		}
	case DO_ACTION: // this stage is always only reached by goto
		do_action:
//logerr("doing action...%s", pconn->req_buf);
//logerr("strcasecmp = %d", !strncasecmp(pconn->req_buf, "GET ", 4));
		pconn->state = DO_ACTION;
		pconn->resp_content_length = -1;
		if (!strncasecmp(pconn->req_buf, "GET ", 4)) 
			handle_http_get_request(pconn);
//		else if (!strncasecmp(pconn->req_buf, "POST ", 5)) 
//			handle_http_post_request(pconn);
		else 
			pconn->http_resp_code = 501; // http method not implemented

		prepare_http_send_resp:
//logerr("prepainrg resp, code = %d", pconn->http_resp_code);
		if (change_state2http_send_resp(pconn) == -1) 
			return; // sock closed upon return
		// switch fall through
	case HTTP_SEND_RESP:
//logerr("sending resp..., code = %d", pconn->http_resp_code);
		if (!(events & EPOLLOUT)) return;
		if (pconn->static_content_fd == -1) {
			if (writev_ex(pconn) == -1) return;
		} else {
			if (write_header(pconn) == -1) return;
			if (sendfile_ex(pconn) == -1) return;
		}
		
		log_http_access(pconn);
		if (pconn->http_resp_code != 200) {
			close_conn(pconn->pheap_node)
			return;
		}
		change_state2http_recv_init
		goto http_recv_init;
	} // switch(pconn->state)
}

static void log_http_access(struct connection_t* pconn) {
	char ip[INET6_ADDRSTRLEN];
	char c;
	if (log_refresh_time(g_accesslog) == -1) return;
	if (pconn->client_addr.sa_family == AF_INET) {
		if (inet_ntop(AF_INET, 
				&(((struct sockaddr_in*)&pconn->client_addr)->sin_addr), 
				ip, sizeof(ip)) == NULL)
			return;
	} else {
		if (inet_ntop(AF_INET6, 
				&(((struct sockaddr_in6*)&pconn->client_addr)->sin6_addr),
				ip, sizeof(ip)) == NULL)
            return;
	}
	c = *pconn->p_end_of_init;
	*pconn->p_end_of_init = 0;
	fprintf(getfp(g_accesslog), "%s %s\"%s\" %d\n", 
		ip, getbuf(g_accesslog), pconn->req_buf, 
		pconn->http_resp_code);
	*pconn->p_end_of_init = c;
}

static int sendfile_ex(struct connection_t* pconn) {
	int err;
	while (1) {
		if ((err = sendfile(pconn->fd, pconn->static_content_fd, 
		  &(pconn->resp_body_write_offset),
		  pconn->resp_content_length - pconn->resp_body_write_offset)) <= 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
                logNclose_conn(pconn->pheap_node, "sendfile error: %s", strerror(errno))
            if (!err)
                logNclose_conn(pconn->pheap_node, "sendfile wrote %d bytes", err)
            return -1;
		}
		if (pconn->resp_content_length == pconn->resp_body_write_offset) {
			setTCP_CORK(pconn, 0);
            return 0;
		}
	}
}

static void setTCP_CORK(struct connection_t* pconn, int i) {
	if ((i && !pconn->tcp_cork) || (!i && pconn->tcp_cork)) {
		if (setsockopt(pconn->fd, IPPROTO_TCP, TCP_CORK, &i,sizeof(i)) == -1)
			logerr("setsockopt TCP_CORK %d error: %s", i, strerror(errno));
		else
			pconn->tcp_cork = i;
	}
}

static int write_header(struct connection_t* pconn) {
	int err;
	if (pconn->resp_header_len == pconn->resp_header_write_offset)
		return 0;
	setTCP_CORK(pconn, 1);
	while (1) {
		if ((err = write(pconn->fd, 
			  pconn->resp_header_buf + pconn->resp_header_write_offset,
			  pconn->resp_header_len - pconn->resp_header_write_offset)) <= 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
                logNclose_conn(pconn->pheap_node, "write error: %s", strerror(errno))
            if (!err)
                logNclose_conn(pconn->pheap_node, "write wrote %d bytes", err)
            return -1;
		}
		if (err != pconn->resp_header_len - pconn->resp_header_write_offset)
			pconn->resp_header_write_offset += err;
		else
			return 0;
	}	
}

static int writev_ex(struct connection_t* pconn) {
	int err;
	while (1) {
    	if ((err = writev(pconn->fd,
        		pconn->writev_s.iov, pconn->writev_s.iovcnt)) <= 0) {
        	if (errno != EAGAIN && errno != EWOULDBLOCK)
            	logNclose_conn(pconn->pheap_node, "writev error: %s", strerror(errno))
			if (!err)
				logNclose_conn(pconn->pheap_node, "writev wrote %d bytes", err)
            return -1;
        }
		if (err != total_length_of_iov(&pconn->writev_s)) {
			adjust_iov(&pconn->writev_s, err);
		} else
			return 0;
    }
}

static void adjust_iov(struct conn_writev_t* w, int wrote_len) {
	int i, len, t;
	struct iovec* p;
	len = 0;
	for (i = 0; i != w->iovcnt; ++i) {
		len += w->iov->iov_len;
		if (len > wrote_len) break;
	}
	w->iov += i;
	w->iovcnt -= i;
	t = len - wrote_len;
	w->iov->iov_base += w->iov->iov_len - t;
	w->iov->iov_len = t;
}

static int total_length_of_iov(struct conn_writev_t* w) {
	int i, len;
	len = 0;
	for (i = 0; i != w->iovcnt; ++i) {
		len += w->iov->iov_len;
		(w->iov)++;
	}
	return len;
}

static int change_state2http_send_resp(struct connection_t* pconn) {
	pconn->state = HTTP_SEND_RESP;
    pconn->resp_header_write_offset = 0;
	pconn->resp_body_write_offset = 0;
	if (prepare_resp_bufs(pconn) == -1) return -1; //sprintf error
	if (!(pconn->events & EPOLLOUT)) {
    	modify_to_EPOLLOUT(pconn);
		return -1;
	}
	return 0;
}

static void modify_to_EPOLLOUT(struct connection_t* pconn) {
	ev.data.ptr = pconn;
	pconn->events |= EPOLLOUT;
    ev.events = pconn->events;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, pconn->fd, &ev) == -1)
    	logNclose_conn(pconn->pheap_node, "EPOLL_CTL_MOD error: %s", strerror(errno))
}

static void handle_http_get_request(struct connection_t* pconn) {
	if ((pconn->static_content_fd = get_fd_from_cache_0copy(fd_cache,
    		pconn->req_buf + 4, &pconn->resp_content_length)) != -1) {
    	pconn->http_resp_code = 200;
        return;
    } else if(!strncmp(pconn->req_buf + 4, "/simple.c", 9)) {
        // TODO dynamic content
        // test: /simple.c?a=2    ===> even number
        if (*(pconn->req_buf + 16)>=48 && *(pconn->req_buf + 16)<=56 && !(*(pconn->req_buf + 16)%2)){
            pconn->resp_content_length = sprintf(pconn->resp_buf, "this is an even number!");
        } else if (*(pconn->req_buf + 16)>=49 && *(pconn->req_buf + 16)<=57 && (*(pconn->req_buf + 16)%2)) {
            pconn->resp_content_length = sprintf(pconn->resp_buf, "this is an odd number~~");
        } else {
            pconn->http_resp_code = 400; // bad request
			pconn->resp_content_length = sprintf(pconn->resp_buf, "length of first parameter must be 1, value must be in [0, 9]");
            return;
        }
        pconn->http_resp_code = 200;
        return;
    } else {
        pconn->http_resp_code = 404; // file not found for http GET method
        return;
    }
}

static char* http_code2str(int code) {
	struct table_t {
		int code;
		char* str;
	};
	static const struct table_t table[] = 
		{{200, "OK"},
		 {400, "Bad Request"},
		 {404, "Not Found"},
		 {413, "Request Entity Too Large"},
		 {501, "Not Implemented"}};
	int i, table_size;
	table_size = sizeof(table) / sizeof(table[0]);
	for (i = 0; i != table_size; ++i) 
		if (code == table[i].code) return table[i].str;
	return table[1].str; // Bad Reqeust
}

static int get_http_headers(struct connection_t* pconn) {
	char* p_next_newline;
	while (1) {
		if ((p_next_newline = strchr(pconn->p_newline + 1, '\n')) != NULL) {
			if (!strncasecmp("Content-Length: ", pconn->p_newline, 16)) 
				pconn->content_length = atoi(pconn->p_newline + 16);
			//if (!strncasecmp("Cookie: ", pconn->p_newline, 8))
              //  pconn->content_length = atoi(pconn->p_newline + 8); // TODO
			// ...
			// double CRLF or LF
			if ((p_next_newline - pconn->p_newline == 1) || 
			  		((p_next_newline - pconn->p_newline == 2) 
					&& (*(pconn->p_newline + 1) == '\r'))) {
				pconn->p_newline = p_next_newline;
				return 1;
			}
			pconn->p_newline = p_next_newline;
			continue;
		} else
			return 0;
	}
}

static char* recv_ex(struct connection_t* pconn, int* perr) {
	char* pc, *p;
	pc = pconn->preq_buf;
	if (pconn->preq_buf - pconn->req_buf == CONN_REQ_BUF_LEN - 1) {
		*perr = -413;
		return pc;
	}
    *perr = recv(pconn->fd, pconn->preq_buf,
    	CONN_REQ_BUF_LEN - 1 - (pconn->preq_buf - pconn->req_buf),0);
    if (*perr == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
        	logNclose_conn(pconn->pheap_node, "recv error: %s", strerror(errno))
        return NULL;
    }
	// in case some fool sends '\0'
	for (p = pc; p != pc + *perr; ++p) {
		if (*p == 0) {
			*perr = -4444;
			return pc;
		}
	}
	*(pconn->preq_buf += *perr) = 0;
	return pc;
}

static int prepare_resp_bufs(struct connection_t* pconn) {
	if (pconn->resp_content_length > 0) {
		if ((pconn->resp_header_len = sprintf(pconn->resp_header_buf,
						"HTTP/1.1 %d %s\r\n"
						"Server: fumin/0.1\r\n"
"Connection: Keep-Alive\r\n"
						"Content-Length: %d\r\n\r\n", 
						pconn->http_resp_code,
                        http_code2str(pconn->http_resp_code),
						pconn->resp_content_length)) < 0) {
			logNclose_conn(pconn->pheap_node, "%s error", "sprintf")
			return -1;
		}
		if (pconn->static_content_fd < 0) {
        	pconn->writev_s.iovs[0].iov_base = pconn->resp_header_buf;
        	pconn->writev_s.iovs[0].iov_len = pconn->resp_header_len;
        	pconn->writev_s.iovs[1].iov_base = pconn->resp_buf;
        	pconn->writev_s.iovs[1].iov_len = pconn->resp_content_length;
        	pconn->writev_s.iov = pconn->writev_s.iovs;
        	pconn->writev_s.iovcnt = 2;
    	}
	} else {
		if ((pconn->resp_header_len = sprintf(pconn->resp_header_buf,
						"HTTP/1.1 %d %s\r\n"
"Connection: Keep-Alive\r\n"
						"Server: fumin/0.1\r\n\r\n",
						pconn->http_resp_code, 
						http_code2str(pconn->http_resp_code))) < 0) {
			logNclose_conn(pconn->pheap_node, "%s error", "sprintf")
			return -1;
		}
		pconn->writev_s.iovs[0].iov_base = pconn->resp_header_buf;
		pconn->writev_s.iovs[0].iov_len = pconn->resp_header_len;
		pconn->writev_s.iov = pconn->writev_s.iovs;
		pconn->writev_s.iovcnt = 1;
	}
	return 0;
}

static void handle_err_event(struct epoll_event* event) {
/*	if (event->events & EPOLLERR)
		logerr("EPOLLERR on fd: %d", ((struct connection_t*)event->data.ptr)->fd);
    if (event->events & EPOLLHUP)
		logerr("EPOLLHUP on fd: %d", ((struct connection_t*)event->data.ptr)->fd);
    if (event->events & EPOLLRDHUP)
        logerr("EPOLLRDHUP on fd: %d", ((struct connection_t*)event->data.ptr)->fd);*/
#if 0
	// when the file descriptor is closed, epoll automatically deletes it from 
	// its queue, so we don't need to explicitly delete the event
	ev.events = 0;
	ev.data.ptr = NULL;
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, event->data.ptr->fd, &ev) == -1) 
		logerr("epoll_ctl EPOLL_CTL_DEL error: %s", strerror(errno));
#endif	
	if (close(((struct connection_t*)event->data.ptr)->fd) == -1) 
		logerr("close fd%d error: %s", ((struct connection_t*)event->data.ptr)->fd, strerror(errno));
	heap_decrease_key(g_pheap, ((struct connection_t*)event->data.ptr)->pheap_node, 2);
    heap_delete_min(g_pheap);
}

static void accept_listen_fd(int listen_fd, struct epoll_event* event) {
	int infd;
	socklen_t in_len;
	struct sockaddr in_addr;
	heap_node* pheap_n;
	if (event->events & (EPOLLERR|EPOLLHUP|EPOLLRDHUP)) {
    	log_listen_fd_errors(event->events)
        exit(1);
    }
	while (1) {
		in_len = sizeof in_addr;
		if ((infd = accept(listen_fd, &in_addr, &in_len)) == -1) {
			if (errno == ECONNABORTED) continue; // client left before accept
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				logerr("accept error: %s", strerror(errno));
			return;
		}
		if (setnonblocking(infd) == -1) {
			logerr("fd%d O_NBLOCK error in accept_listen_fd");
			if (close(infd) == -1)
				logerr("close fd%d error: %s", infd, strerror(errno));
			continue;
		}

		pheap_n = heap_insert(g_pheap, *gp_current_timestamp + g_timeout_interval);
		pheap_n->value.client_addr = in_addr;
		pheap_n->value.fd = infd;
		pheap_n->value.state = HTTP_RECV_INIT;
		pheap_n->value.preq_buf = pheap_n->value.req_buf;
		*pheap_n->value.req_buf = 0;
		pheap_n->value.static_content_fd = -1;
		pheap_n->value.pheap_node = pheap_n;
		pheap_n->value.tcp_cork = 0;
		pheap_n->value.content_length = -1;
		ev.data.ptr = &pheap_n->value;
		pheap_n->value.events = ev.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &ev) == -1) 
			logNclose_conn(pheap_n, "EPOLL_CTL_ADD error: %s", strerror(errno))
	}
}

static int socket_bind_listen (const char port[]) {
	struct addrinfo hints, *ai, *p;
	int listener, yes = 1, defer_accept_timeout = 1, rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;//AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port, &hints, &ai)) != 0) 
		logNreturn("getaddrinfo: %s", gai_strerror(rv))

	for (p = ai; p != NULL; p = p->ai_next) {
		listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listener < 0) {
			continue;
		}

		// lose the pesky "address already in use" error message
		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		setsockopt(listener, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept_timeout, sizeof(int));

		if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
			close(listener);
			continue;
		}

		break;
	}
	freeaddrinfo(ai);
	if (p == NULL) logNreturn("failed to bind")

	if (setnonblocking(listener) == -1) return -1;
	if (listen(listener, SOMAXCONN) == -1) 
		logNreturn("listen error: %s", strerror(errno))

	return listener;
}

int setnonblocking(int conn_sock) {
	int val;
	if ((val = fcntl(conn_sock, F_GETFL, 0)) < 0) 
		logNreturn("setnonblocking::fcntl() F_GETFL: %s", strerror(errno))
	
	val |= O_NONBLOCK;
	
	if (fcntl(conn_sock, F_SETFL, val) < 0) 
		logNreturn("setnonblocking::fcntl() F_SETFL: %s", strerror(errno))

	return 0;
}

void daemonize(const char *cmd, const char errlog_file[]) { /* Figure 13.1 */
    int                 i, fd0, fd1, fd2;
    pid_t               pid;
    struct rlimit       rl;
    struct sigaction    sa;
    /*
     * Clear file creation mask.
     */
    umask(0);
    /*
     * Get maximum number of file descriptors.
     */
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		fprintf(stderr, "%s: can't get file limit\n", cmd);
		exit(1);
	}
    /*
     * Become a session leader to lose controlling TTY.
     */
    if ((pid = fork()) < 0) {
		fprintf(stderr, "%s: can't fork\n", cmd);
		exit(1);
	}
    else if (pid != 0) /* parent */
        exit(0);
    setsid();
    /*
     * Ensure future opens won't allocate controlling TTYs.
     */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
		fprintf(stderr, "%s: can't ignore SIGHUP\n");
		exit(1);
	}
    if ((pid = fork()) < 0) {
		fprintf(stderr, "%s: can't fork\n", cmd);
        exit(1);
	}
    else if (pid != 0) /* parent */
        exit(0);
    /*
     * Change the current working directory to the root so
     * we won't prevent file systems from being unmounted.
     */
    if (chdir("/") < 0) {
		fprintf(stderr, "%s: can't change directory to /\n");
		exit(1);
	}
    /*
     * Close all open file descriptors.
     */
    if (rl.rlim_max == RLIM_INFINITY)
        rl.rlim_max = 1024;
    for (i = 3; i < rl.rlim_max; i++)
        close(i);

	if ((g_errlog = newLogger(errlog_file)) == NULL) {
		fprintf(stderr, "newLogger error: %s\n", errlog_file);
		exit(1);
	}	

    /*
     * Attach file descriptors 0, 1, and 2 to /dev/null.
     */
	close(0); close(1); close(2);
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);
    /*
     * Initialize the log file.
     */
    /*openlog(cmd, LOG_CONS, LOG_DAEMON);
    if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
        syslog(LOG_ERR, "unexpected file descriptors %d %d %d",
          fd0, fd1, fd2);
        exit(1);
    }*/
}

void pr_exit(pid_t child_pid, int status) { 
    if (WIFEXITED(status)) 
        logerr("worker %d normal termination, exit status = %d", 
                child_pid, WEXITSTATUS(status)); 
    else if (WIFSIGNALED(status)) 
        logerr("worker %d abnormal termination, signal number = %d%s", 
                child_pid, WTERMSIG(status), 
#ifdef  WCOREDUMP 
                WCOREDUMP(status) ? " (core file generated)" : "");
#else 
                ""); 
#endif 
    else if (WIFSTOPPED(status)) 
        logerr("worker %d child stopped, signal number = %d", 
                child_pid, WSTOPSIG(status)); 
} 

int lockfile(int fd) {
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    return(fcntl(fd, F_SETLK, &fl));
}

int already_running(const char LOCKFILE[]) {
    int     fd;
    char    buf[16];
    //char* LOCKFILE = pidf;
    fd = open(LOCKFILE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
		logerr("can't open %s: %s", LOCKFILE, strerror(errno));
        exit(1);
    }
    if (lockfile(fd) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            close(fd);
            return(1);
        }
		logerr("can't lock %s: %s", LOCKFILE, strerror(errno));
        exit(1);
    }
    ftruncate(fd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(fd, buf, strlen(buf)+1);
    return(0);
}
