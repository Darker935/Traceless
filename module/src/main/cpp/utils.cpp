#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <iostream>
#include <iomanip>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <tuple>
#include <cstdint>
#include <sys/mman.h>
#include <link.h>
#include <fcntl.h>
#include "log.h"
// Adicione estas linhas no topo
#include <functional>  // Para std::function
#include <android/log.h>  // Para ANDROID_LOG_*
#include <sys/stat.h>

inline std::optional<std::pair<dev_t, ino_t>> devinoby(const char *lib) {
    struct State {
        const char *needle;
        std::optional<std::pair<dev_t, ino_t>> result;
    } state = {lib};

    dl_iterate_phdr([](struct dl_phdr_info *info, size_t, void *data) -> int {
        auto *s = static_cast<State *>(data);
        if (info->dlpi_name && strstr(info->dlpi_name, s->needle)) {
            struct stat st{};
            if (stat(info->dlpi_name, &st) == 0) {
                s->result = std::make_pair(st.st_dev, st.st_ino);
                return 1; // Stop iteration
            }
        }
        return 0; // Continue
    }, &state);

    return state.result;
}

inline std::pair<dev_t, ino_t>
devinobymap(const std::string &lib, bool useFind = false, unsigned int *ln = nullptr) {
    std::ifstream maps("/proc/self/maps");
    unsigned int index = 0;
    std::string line;
    std::string needle = "/" + lib;
    while (std::getline(maps, line)) {
        if (ln && index < *ln) {
            index++;
            continue;
        }
        if (line.size() >= needle.size() && ((useFind && line.find(needle) != std::string::npos) ||
                                             line.compare(line.size() - needle.size(),
                                                          needle.size(), needle) == 0)) {
            std::istringstream iss(line);
            std::string addr, perms, offset, dev, inode_str;
            iss >> addr >> perms >> offset >> dev >> inode_str;
            std::istringstream devsplit(dev);
            std::string major_hex, minor_hex;
            if (std::getline(devsplit, major_hex, ':') &&
                std::getline(devsplit, minor_hex)) {
                int major = std::stoi(major_hex, nullptr, 16);
                int minor = std::stoi(minor_hex, nullptr, 16);
                dev_t devnum = makedev(major, minor);
                ino_t inode = std::stoul(inode_str);
                if (ln)
                    *ln = index;
                return {devnum, inode};
            }
        }
        index++;
    }
    if (ln)
        *ln = -1;
    return {dev_t(0), ino_t(0)};
}

inline int forkcall(const std::function<int()> &lambda) {
    pid_t pid = fork();
    if (pid == -1)
        return -1;
    if (pid == 0) {
        exit(lambda());
    } else {
        int status = -1;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
    }
    return -1;
}

static int pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}

inline bool switchnsto(pid_t pid) {
    int fd = pidfd_open(pid, 0);
    if (fd != -1) {
        int res = setns(fd, CLONE_NEWNS);
        close(fd);
        return res == 0;
    } else {
        LOGE("pidfd_open: %s", strerror(errno));
    }
    std::string path = "/proc/" + std::to_string(pid) + "/ns/mnt";
    fd = open(path.c_str(), O_RDONLY);
    if (fd != -1) {
        int res = setns(fd, 0);
        close(fd);
        return res == 0;
    } else {
        LOGE("open: %s", strerror(errno));
    }
    return false;
}