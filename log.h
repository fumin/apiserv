#ifndef _LOG_H_
#define _LOG_H_

#include <time.h>
#include <stdio.h>

#define STRINGTIFY_logfl(_logger, _file, _line, ...) log_file_line(_logger, _file, #_line, __VA_ARGS__)
#define TOSTRING_logfl(_logger, _file, _line, ...) STRINGTIFY_logfl(_logger, _file, _line, __VA_ARGS__)
#define logfl(_logger, ...) TOSTRING_logfl(_logger, __FILE__, __LINE__, __VA_ARGS__)

extern time_t* gp_current_timestamp;
extern pid_t g_logpid;

typedef struct logger_t* Logger;
FILE* getfp(Logger);
char* getbuf(Logger);
Logger newLogger(const char[]);
Logger newLogger2(const char[], Logger);
int log_setitimer(Logger);
void deleteLogger(Logger);
int log_refresh_time(Logger);
void logw(Logger, const char*, ...);
void reopen_logfile(Logger, Logger);

#endif
