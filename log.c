#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include "log.h"

#define BUF_SIZE 4096
#define LOGFILE_PATH_LEN 512

time_t* gp_current_timestamp;
pid_t g_logpid;

static void log_alarm_signal_handler(int sig) {
	*gp_current_timestamp = time(NULL);
}

struct logger_t {
	FILE* fp;
	char buffer[BUF_SIZE];
	time_t last_generated_ts;
	char* buf_timestamp_end_pointer;
	int buf_len;
	char logfile_path[LOGFILE_PATH_LEN];
};

FILE* getfp(Logger logger) {
	return logger->fp;
}

char* getbuf(Logger logger) {
	return logger->buffer;
}

Logger newLogger(const char fname[]) {
	return newLogger2(fname, NULL);
}

Logger newLogger2(const char fname[], Logger errl) {
	Logger logger;
	FILE* flog;
	int dev_zero_fd;
	g_logpid = getpid();
	flog = (errl && errl->fp) ? errl->fp : stderr; 
	if (strlen(fname) > LOGFILE_PATH_LEN - 2) return NULL;
	if ((logger = (Logger)malloc(sizeof(struct logger_t))) == NULL) {
		fprintf(flog, 
			"(%s.%s) pid%d malloc error: %s\n", 
			__FILE__, __LINE__, g_logpid, strerror(errno));
		exit(1);
	}
	if ((logger->fp = fopen(fname, "a")) == NULL) {
		fprintf(flog, 
			"(%s.%s) pid%d can't open %s: %s\n",
			__FILE__, __LINE__, g_logpid, fname, strerror(errno));
		exit(1);
	}
	strcpy(logger->logfile_path, fname);
	if (!errl) {
		if ((dev_zero_fd = open("/dev/zero", O_RDWR)) < 0) {
			fprintf(flog,
            	"(%s.%s) pid%d can't open /dev/zero: %s\n",
            	__FILE__, __LINE__, g_logpid, strerror(errno));
        	exit(1);
		}
		if ((gp_current_timestamp = mmap(0, sizeof(time_t), 
	  	  PROT_READ | PROT_WRITE, MAP_SHARED, dev_zero_fd, 0)) == MAP_FAILED) {
			fprintf(flog,
            	"(%s.%s) pid%d mmap error: %s\n",
            	__FILE__, __LINE__, g_logpid, strerror(errno));
        	exit(1);
		}
		close(dev_zero_fd);
		if (log_setitimer(logger) == -1) {
			fprintf(flog, "newLogger.log_setitimer error\n");
        	exit(1);
		}
	}
	return logger;
}

void reopen_logfile(Logger logger, Logger errl) {
	FILE* flog;
	g_logpid = getpid();
	flog = (errl && errl->fp) ? errl->fp : stderr;
	if (fclose(logger->fp)) {
		fprintf(flog,
            "(%s.%s) pid%d can't fclose %s: %s\n",
            __FILE__, __LINE__, g_logpid, logger->logfile_path, strerror(errno));
        exit(1);
	}
	if ((logger->fp = fopen(logger->logfile_path, "a")) == NULL) {
        fprintf(flog,
            "(%s.%s) pid%d can't open %s: %s\n",
            __FILE__, __LINE__, g_logpid, 
			logger->logfile_path, strerror(errno));
        exit(1);
    }
}

int log_setitimer(Logger logger) {
	struct sigaction act;
	struct itimerval interval;

	g_logpid = getpid();
	*gp_current_timestamp = time(NULL);
	strftime(logger->buffer, sizeof(logger->buffer),
    	"%Y-%m-%d %H:%M:%S: ", localtime(gp_current_timestamp));
    //memset(&act, 0, sizeof(act));
    act.sa_handler = log_alarm_signal_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGALRM, &act, NULL) < 0) {
        fprintf(logger->fp,
            "%s(%s.%s) pid%d log_setitimer.sigaction error: %s\n", 
			logger->buffer, __FILE__, __LINE__, g_logpid, strerror(errno));
		fflush(logger->fp);
        return -1;
    }

    interval.it_interval.tv_sec = 1;
    interval.it_interval.tv_usec = 0;
    interval.it_value.tv_sec = 1;
    interval.it_value.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &interval, NULL)) {
        fprintf(logger->fp,
            "%s(%s.%s) pid%d log_setitimer.setitimer error: %s\n", 
			logger->buffer, __FILE__, __LINE__, g_logpid, strerror(errno));
		fflush(logger->fp);
        return -1;
    }
	return 0;
}

void deleteLogger(Logger logger) {
	fclose(logger->fp);
	free(logger);
}

int log_refresh_time(Logger logger) {
	int err;
	if (*gp_current_timestamp != logger->last_generated_ts) {
        if ((err = strftime(logger->buffer, sizeof(logger->buffer),
          "[%d/%b/%Y:%H:%M:%S %z] ", localtime(gp_current_timestamp))) == 0)
			return -1;
        logger->buf_len = BUF_SIZE - err;
        logger->buf_timestamp_end_pointer = logger->buffer + err;
        logger->last_generated_ts = *gp_current_timestamp;
    }
	return 0;
}

void logw(Logger logger, const char* fmt, ...) {
	va_list ap;
	int len; //for write
	// cache generated timestamp
	if (log_refresh_time(logger) == -1) return;

	va_start(ap, fmt);
	len = vsnprintf(logger->buf_timestamp_end_pointer, logger->buf_len, fmt, ap);
	va_end(ap);

	if (len < 0) return;
	*(logger->buf_timestamp_end_pointer + len) = '\n';
	write(fileno(logger->fp), logger->buffer, BUF_SIZE - logger->buf_len + len + 1);
	//fprintf(logger->fp, "%s%s", logger->buffer, "\n");fflush(logger->fp);
}

void log_file_line(Logger logger, 
	const char* file, const char* line, const char* fmt, ...) {
	int file_line_len;
	va_list ap;
	int len;
    // cache generated timestamp
	if (log_refresh_time(logger) == -1) return;

	if ((file_line_len = snprintf(logger->buf_timestamp_end_pointer, 
			logger->buf_len, "(%s.%s) pid[%d] ", file, line, g_logpid)) < 0)
		return;

    va_start(ap, fmt);
    len = vsnprintf(logger->buf_timestamp_end_pointer + file_line_len, 
		logger->buf_len - file_line_len, fmt, ap);
    va_end(ap);

	if (len < 0) return;
	*(logger->buf_timestamp_end_pointer + file_line_len + len) = '\n';
	write(fileno(logger->fp), logger->buffer, BUF_SIZE - logger->buf_len + file_line_len + len + 1);
    //fprintf(logger->fp, "%s%s", logger->buffer, "\n");fflush(logger->fp);
}

