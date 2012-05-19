#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

int lockfile(int fd) { 
    struct flock fl; 
    fl.l_type = F_WRLCK; 
    fl.l_start = 0; 
    fl.l_whence = SEEK_SET; 
    fl.l_len = 0; 
    return(fcntl(fd, F_SETLK, &fl));
} 

int already_running(void) 
{ 
    int     fd; 
    char    buf[16]; 
	char* LOCKFILE = "/usr/local/adon/fumin/myserver/test/this.pid";
    fd = open(LOCKFILE, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); 
    if (fd < 0) { 
        fprintf(stderr, "can't open %s: %s", LOCKFILE, strerror(errno));
        exit(1); 
    } 
    if (lockfile(fd) < 0) { 
        if (errno == EACCES || errno == EAGAIN) { 
            close(fd); 
            return(1); 
        } 
        fprintf(stderr, "can't lock %s: %s", LOCKFILE, strerror(errno));
        exit(1); 
    } 
    ftruncate(fd, 0); 
    sprintf(buf, "%ld", (long)getpid()); 
    write(fd, buf, strlen(buf)+1); 
    return(0); 
} 

FILE* fp;
int sig_usr_bool;

void sig_usr(int signo) {
	sig_usr_bool = 1;
}

int main(void) {
	int i, j, k;
	struct sigaction act;
	sig_usr_bool = 0;
	if(already_running() == -1) return -1;
	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_usr;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &act, NULL) < 0) {
		fprintf(stderr, "sigaction error: %s\n", strerror(errno));
		return -1;
	}
	if ((fp = fopen("/usr/local/adon/fumin/myserver/test/pop", "a")) == NULL) {
		fprintf(stderr, "can't open!\n");
		return -1;
	} else {
		printf("succeed!\n");
	}
	for (i = 0; i != 900000000; ++i) {
		for (j = 0; j != 900000000; ++j) {
			for(k = 0; k != 900000000; ++k) {
				if ((k % 10000000) == 0) printf("%d\n", k);
				if (!sig_usr_bool) {
					fprintf(fp, "%d.%d.%d\n", i, j, k); 
				} else {
					fclose(fp);
					fopen("/usr/local/adon/fumin/myserver/test/pop", "a");
					fprintf(fp, "%d.%d.%d\n", i, j, k);
					sig_usr_bool = 0;
				}
			}
		}
	}
	fclose(fp);
	return 0;
}
