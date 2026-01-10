#include <unistd.h>
#include "../include/posix.hpp"

char is_running_as_root() {
    return geteuid() == 0;
}
