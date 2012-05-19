#ifndef _FD_CACHE_H_
#define _FD_CACHE_H_

#include <unistd.h>
#include "log.h"

typedef struct fd_cache_t* FDcache;

FDcache newFDcache(const char[], Logger);
void deleteFDcache(FDcache);
int get_fd_from_cache(FDcache, const char[], off_t*);
int get_fd_from_cache_0copy(FDcache, char*, off_t*);
void clear_fd_cache(FDcache);

#endif
