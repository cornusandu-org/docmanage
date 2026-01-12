#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdio>
#include "../include/posix.hpp"

char is_running_as_root() {
    return geteuid() == 0;
}

char check_root_owner_and_0600(const char* path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        perror("stat failed");
        return false;
    }

    /* Check owner is root */
    if (st.st_uid != 0) {
        return false;
    }

    /* Mask only permission bits */
    mode_t perms = st.st_mode & 0777;

    /* Check permissions exactly 0600 */
    if (perms != 0600) {
        return false;
    }

    return true;
}
