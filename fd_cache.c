#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "fd_cache.h"

#define FD_CACHE_LEN 33
#define FD_CACHE_MAX_PATH_LEN 128
#define FD_CACHE_DIR_PREFIX_LEN 512

struct pathfd_t {
	int fd;
	off_t st_size;
	char path[FD_CACHE_MAX_PATH_LEN];
};

struct fd_cache_t {
	struct pathfd_t a[FD_CACHE_LEN];
	struct pathfd_t* aend;
	char dir_prefix_buf[FD_CACHE_DIR_PREFIX_LEN];
	char* dir_prefix_pend;
	Logger logger;
};

FDcache newFDcache(const char dir_prefix[], Logger errl) {
	FILE* filog;
	FDcache fd_cache;
	if (strlen(dir_prefix) > 
		FD_CACHE_DIR_PREFIX_LEN - FD_CACHE_MAX_PATH_LEN) return NULL;
	if ((fd_cache = (FDcache)malloc(sizeof(struct fd_cache_t))) == NULL) {
		logfl(errl, "malloc error: %s", strerror(errno));
        exit(1);
	}
	strcpy(fd_cache->dir_prefix_buf, dir_prefix);
	fd_cache->dir_prefix_pend = fd_cache->dir_prefix_buf + strlen(dir_prefix);
	fd_cache->aend = fd_cache->a;
	fd_cache->logger = errl;
	return fd_cache;
}

void deleteFDcache(FDcache fd_cache) {
	free(fd_cache);
}

int get_fd_from_cache_0copy(FDcache fd_cache, char* path, off_t* pst_size) {
	char* pchar;
	char c;
	int fd;
	if (fd_cache == NULL) return -1;
	for (pchar = path; *pchar; ++pchar) {
		if (*pchar == '?' || *pchar == ' ') {
			c = *pchar;
			*pchar = 0;
			fd = get_fd_from_cache(fd_cache, path, pst_size);
			*pchar = c;
			return fd;
		}
	}
	return -1;
}

static int add_fd_to_cache(FDcache fd_cache,
    const char path[], off_t* pst_size) {
    struct stat stat_buf;
	if (fd_cache == NULL) return -1;
    strcpy(fd_cache->dir_prefix_pend, path);
    if (fd_cache->aend - fd_cache->a == FD_CACHE_LEN) return -1;
    if ((fd_cache->aend->fd = open(fd_cache->dir_prefix_buf, O_RDONLY|O_NONBLOCK)) == -1)
        return -1;
    if (fstat(fd_cache->aend->fd, &stat_buf) == -1) {
        logfl(fd_cache->logger, "fstat error: %s", strerror(errno));
        return -1;
    }
    *pst_size = fd_cache->aend->st_size = stat_buf.st_size;
    strcpy(fd_cache->aend->path, path);
    fd_cache->aend++;
    return (fd_cache->aend - 1)->fd;
}

int get_fd_from_cache(FDcache fd_cache, const char path[], off_t* pst_size) {
	struct pathfd_t* p;
	int fd;
	struct stat stat_buf;
	if (fd_cache == NULL) return -1;
	if (strlen(path) >= FD_CACHE_MAX_PATH_LEN - 1) return -1;
	for (p = fd_cache->a; p != fd_cache->aend; ++p) {
		if (!strcmp(p->path, path)) {
			*pst_size = p->st_size;
			return p->fd;
		}
	} 
	if ((fd = add_fd_to_cache(fd_cache, path, pst_size)) == -1) {
		if ((fd = open(fd_cache->dir_prefix_buf, O_RDONLY|O_NONBLOCK)) == -1)
			return -1;
    	if (fstat(fd, &stat_buf) == -1) {
        	logfl(fd_cache->logger, "fstat error: %s", strerror(errno));
        	return -1;
    	}
		*pst_size = stat_buf.st_size;
		return fd;
	} else {
		return fd;
	}
}

void clear_fd_cache(FDcache fd_cache) {
	fd_cache->aend = fd_cache->a;
}
