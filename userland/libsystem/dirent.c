/*
 * Kiseki OS - Directory Operations Implementation
 */

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syscall.h>

DIR *opendir(const char *name)
{
    int fd = open(name, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return NULL;

    DIR *dirp = (DIR *)malloc(sizeof(DIR));
    if (dirp == NULL) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }

    dirp->fd = fd;
    dirp->buf_pos = 0;
    dirp->buf_len = 0;

    return dirp;
}

struct dirent *readdir(DIR *dirp)
{
    if (dirp == NULL) {
        errno = EBADF;
        return NULL;
    }

    /* If we've consumed all buffered entries, fetch more from kernel */
    if (dirp->buf_pos >= dirp->buf_len) {
        long ret = syscall4(SYS_getdirentries,
                            (long)dirp->fd,
                            (long)dirp->buf,
                            (long)sizeof(dirp->buf),
                            0);
        if (ret <= 0) {
            if (ret < 0)
                errno = (int)(-ret);
            return NULL;    /* End of directory or error */
        }
        dirp->buf_len = (size_t)ret;
        dirp->buf_pos = 0;
    }

    /* Return current entry and advance */
    struct dirent *entry = (struct dirent *)(dirp->buf + dirp->buf_pos);

    /* Validate reclen to prevent infinite loop */
    if (entry->d_reclen == 0 || dirp->buf_pos + entry->d_reclen > dirp->buf_len) {
        /* Corrupt or end of data */
        dirp->buf_pos = dirp->buf_len;
        return NULL;
    }

    dirp->buf_pos += entry->d_reclen;

    return entry;
}

int closedir(DIR *dirp)
{
    if (dirp == NULL) {
        errno = EBADF;
        return -1;
    }

    int ret = close(dirp->fd);
    free(dirp);
    return ret;
}

void rewinddir(DIR *dirp)
{
    if (dirp == NULL)
        return;
    lseek(dirp->fd, 0, SEEK_SET);
    dirp->buf_pos = 0;
    dirp->buf_len = 0;
}
