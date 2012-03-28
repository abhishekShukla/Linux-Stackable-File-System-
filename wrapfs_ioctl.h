#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
             
#define WRAPFS_IOCSETD  _IOW(WRAPFS_MAGIC, 2 , char *)    
#define WRAPFS_MAGIC 's'
