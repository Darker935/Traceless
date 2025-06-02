/*
 * Traceless - Zygisk Module
 * Copyright 2025
 *
 * This module aims to hide Magisk/root related mounts from processes
 * specified in the Magisk DenyList by leveraging Zygisk and its
 * companion process feature.
 */
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include "mountsinfo.cpp"
#include "utils.cpp"
#include <sys/mount.h>
#include <functional>
#include <set>
#include <string>
#include <vector>
#include <system_error>
#include <map>
#include <mutex>
#include <errno.h>
#include <cstring>
#include "zygisk.hpp"
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <string.h>
#include <thread>

//typedef void* (*dlopen_fn_t)(const char*, int);
//
//static dlopen_fn_t original_dlopen = nullptr;
//
//static void* my_dlopen(const char* filename, int flags) {
////    if (filename && strstr(filename, "libc++_shared.so")) {
////        void* handle = original_dlopen("/data/adb/modules/traceless/lib/arm64-v8a/libc++_shared.so", flags);
////        if (handle) {
////            return handle;
////        }
////    }
//    return original_dlopen(filename, flags);
//}
//
//__attribute__((constructor))
//void init_dlopen_hook() {
//    original_dlopen = reinterpret_cast<dlopen_fn_t>(dlsym(RTLD_NEXT, "dlopen"));
//
//    void* libdl = dlopen("libdl.so", RTLD_NOW);
//    if (libdl) {
//        void** dlopen_ptr = reinterpret_cast<void**>(dlsym(libdl, "dlopen"));
//        if (dlopen_ptr) {
//            *dlopen_ptr = reinterpret_cast<void*>(my_dlopen);
//        }
//        dlclose(libdl);
//    }
//}

#define LOG_TAG "Traceless"
#define TL_LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define TL_LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define TL_LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define TL_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// --- Configuration ---
static const std::set<std::string> suspicious_mount_sources = {
        "magisk",
        "KSU",
        "APatch",
        "worker"
};

enum Advice {
    NORMAL = 0,
    MODULE_CONFLICT = 2,
};

enum State {
    SUCCESS = 0,
    FAILURE = 1
};

static const std::string magisk_data_path_prefix = "/data/adb";
static const std::string magisk_modules_path_prefix = "/data/adb/modules/";
static const char *const maps_filter_target = "jit-cache-zygisk_traceless";
static const char *const self_maps_path = "/proc/self/maps";
static const char *const pid_maps_prefix = "/proc/";
static const char *const maps_suffix = "/maps";

// --- Zygisk Module Implementation ---
int (*original_unshare)(int) = nullptr;

static FILE *(*original_fopen)(const char *, const char *) = nullptr;

static char *(*original_fgets)(char *, int, FILE *) = nullptr;

static int (*original_open)(const char *, int, ...) = nullptr;

static int (*original_openat)(int, const char *, int, ...) = nullptr;

static ssize_t (*original_read)(int, void *, size_t) = nullptr;

static ssize_t (*original_pread64)(int, void *, size_t, off64_t) = nullptr;

static int (*original_close)(int) = nullptr;

// Flag to indicate if we are currently processing a /proc/.../maps file via fopen/fgets
static thread_local bool filtering_maps_stream = false; // Use thread_local for safety

// Structure to hold state for filtered file descriptors (using pipes)
struct FilteredFdInfo {
    std::string original_path;
    // Add any other relevant state if needed
};

// Map to track fake FDs (pipe read ends) associated with filtered maps files
// Key: fake_fd (pipe read end), Value: Info about the original file
static std::map<int, FilteredFdInfo> filtered_fds;
static std::mutex filtered_fds_mutex; // Mutex to protect access to the map


// Helper function to check if a path is a proc maps file
static bool isProcMapsFile(const char *path) {
    if (!path) return false;
    if (strcmp(path, self_maps_path) == 0) return true;
    if (strncmp(path, pid_maps_prefix, strlen(pid_maps_prefix)) == 0) {
        const char *suffix_ptr = strstr(path + strlen(pid_maps_prefix), maps_suffix);
        // Ensure it ends exactly with "/maps"
        return suffix_ptr != nullptr && suffix_ptr[strlen(maps_suffix)] == '\0';
    }
    return false;
}

// Helper function to read entire FD content into a string
static std::string readFdToString(int fd) {
    std::stringstream ss;
    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = TEMP_FAILURE_RETRY(::read(fd, buffer, sizeof(buffer)))) > 0) {
        ss.write(buffer, bytes_read);
    }
    // Check for read error
    if (bytes_read < 0) {
        TL_LOGE("readFdToString: Error reading fd %d: %s", fd, strerror(errno));
        return ""; // Return empty on error
    }
    return ss.str();
}

// Helper function to filter maps content (string version)
static std::string filterMapsContent(const std::string &content) {
    std::stringstream input_ss(content);
    std::stringstream output_ss;
    std::string line;
    while (std::getline(input_ss, line)) {
        if (line.find(maps_filter_target) == std::string::npos) {
            output_ss << line << "\n";
        }
    }
    return output_ss.str();
}


static int reshare(int flags) {
    errno = 0;
    return flags == CLONE_NEWNS ? 0 : original_unshare(flags & ~CLONE_NEWNS);
}

// Hook for fopen (unchanged, uses thread_local flag)
static FILE *my_fopen(const char *path, const char *mode) {
    if (!original_fopen) {
        TL_LOGE("my_fopen: original_fopen is null!");
        errno = EFAULT;
        return nullptr;
    }
    if (isProcMapsFile(path)) {
        TL_LOGD("my_fopen: Hooked fopen for maps file: %s", path);
        filtering_maps_stream = true;
    } else {
        filtering_maps_stream = false;
    }
    return original_fopen(path, mode);
}

// Hook for fgets (unchanged, uses thread_local flag)
static char *my_fgets(char *s, int size, FILE *stream) {
    if (!original_fgets) {
        TL_LOGE("my_fgets: original_fgets is null!");
        return nullptr;
    }
    if (!filtering_maps_stream) {
        return original_fgets(s, size, stream);
    }
    char *result;
    while (true) {
        result = original_fgets(s, size, stream);
        if (!result) {
            filtering_maps_stream = false; // Reset flag on EOF/error
            break;
        }
        if (strstr(s, maps_filter_target) == nullptr) {
            break; // Line is okay
        }
        TL_LOGD("my_fgets: Filtering line containing 	'%s'", maps_filter_target);
        // Loop to read next line
    }
    return result;
}

// Writer thread function
void pipeWriterThreadFunc(int write_fd, std::string content) {
    size_t total_written = 0;
    const char *data = content.c_str();
    size_t data_len = content.length();
    while (total_written < data_len) {
        ssize_t written = TEMP_FAILURE_RETRY(
                ::write(write_fd, data + total_written, data_len - total_written)
        );
        if (written <= 0) break;
        total_written += written;
    }
    ::close(write_fd);
}

// Common logic for open/openat hooks
static int handle_open_maps(const char *path, int real_fd) {
    TL_LOGD("handle_open_maps: Opened maps file: %s (real_fd: %d)", path, real_fd);

    // 1. Read original content
    std::string original_content = readFdToString(real_fd);

    // 2. Close the real FD immediately
    if (original_close(real_fd) != 0) {
        TL_LOGW("handle_open_maps: Failed to close real_fd %d: %s", real_fd, strerror(errno));
        // Continue anyway, but log
    }

    if (original_content.empty()) {
        TL_LOGE("handle_open_maps: Failed to read content from real_fd %d for path %s", real_fd,
                path);
        errno = EIO; // Input/output error
        return -1;
    }

    // 3. Filter content
    std::string filtered_content = filterMapsContent(original_content);

    // 4. Create a pipe
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) == -1) {
        TL_LOGE("handle_open_maps: Failed to create pipe for %s: %s", path, strerror(errno));
        errno = EMFILE; // Too many open files (or pipe error)
        return -1;
    }
    int read_pipe_fd = pipe_fds[0];
    int write_pipe_fd = pipe_fds[1];

    // 5. Write filtered content to the pipe
    std::thread writer_thread(pipeWriterThreadFunc, write_pipe_fd, std::move(filtered_content));
    writer_thread.detach();

    // 6. Store the mapping from fake_fd (read pipe) to original path
    {
        std::lock_guard<std::mutex> lock(filtered_fds_mutex);
        filtered_fds[read_pipe_fd] = {path ? std::string(path) : "<unknown>"};
        TL_LOGD("handle_open_maps: Created pipe %d -> %d for filtered maps %s. Returning fake_fd %d",
                read_pipe_fd, write_pipe_fd, path, read_pipe_fd);
    }

    // 7. Return the read end of the pipe as the fake FD
    return read_pipe_fd;
}

// Hook for open
static int my_open(const char *path, int flags, ...) {
    if (!original_open) {
        TL_LOGE("my_open: original_open is null!");
        errno = EFAULT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (isProcMapsFile(path)) {
        TL_LOGD("my_open: Intercepted open for maps file: %s", path);
        // Call original open first to get the real FD
        // IMPORTANT: We ignore O_CREAT, O_WRONLY, O_APPEND etc. for maps files
        // Force read-only open for the real file.
        int real_fd = original_open(path, O_RDONLY | O_CLOEXEC); // Use O_CLOEXEC for safety
        if (real_fd < 0) {
            TL_LOGE("my_open: Original open failed for %s: %s", path, strerror(errno));
            return -1; // Return original error
        }
        // Handle filtering and return fake FD (pipe read end)
        return handle_open_maps(path, real_fd);
    } else {
        // Not a maps file, call original open directly
        return original_open(path, flags, mode);
    }
}

// Hook for openat
static int my_openat(int dirfd, const char *path, int flags, ...) {
    if (!original_openat) {
        TL_LOGE("my_openat: original_openat is null!");
        errno = EFAULT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    // Check if it's an absolute path or relative to /proc
    // This check might need refinement depending on how apps use openat for /proc
    bool potentially_maps = isProcMapsFile(path);
    // If path is relative, we might need to resolve it based on dirfd, which is complex.
    // For now, we primarily handle absolute paths passed to openat.

    if (potentially_maps) {
        TL_LOGD("my_openat: Intercepted openat for maps file: %s (dirfd: %d)", path, dirfd);
        // Similar to open, call original openat first, forcing read-only.
        int real_fd = original_openat(dirfd, path, O_RDONLY | O_CLOEXEC);
        if (real_fd < 0) {
            TL_LOGE("my_openat: Original openat failed for %s: %s", path, strerror(errno));
            return -1;
        }
        // Handle filtering and return fake FD
        return handle_open_maps(path, real_fd);
    } else {
        // Not a maps file, call original openat directly
        return original_openat(dirfd, path, flags, mode);
    }
}

// Hook for read
static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!original_read) {
        TL_LOGE("my_read: original_read is null!");
        errno = EFAULT;
        return -1;
    }

    bool is_filtered_fd;
    {
        std::lock_guard<std::mutex> lock(filtered_fds_mutex);
        is_filtered_fd = filtered_fds.count(fd);
    }

    if (is_filtered_fd) {
        // Reading from our pipe (filtered content)
        TL_LOGD("my_read: Reading from filtered fd %d", fd);
        return original_read(fd, buf, count); // Read directly from the pipe
    } else {
        // Normal read
        return original_read(fd, buf, count);
    }
}

// Hook for pread64
static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    if (!original_pread64) {
        TL_LOGE("my_pread64: original_pread64 is null!");
        errno = EFAULT;
        return -1;
    }

    bool is_filtered_fd;
    {
        std::lock_guard<std::mutex> lock(filtered_fds_mutex);
        is_filtered_fd = filtered_fds.count(fd);
    }

    if (is_filtered_fd) {
        // Reading from our pipe. Pipes don't support pread (seeking).
        // We *could* simulate it by reading and discarding up to offset, but that's inefficient
        // and breaks subsequent reads. The simplest is to return an error.
        TL_LOGW("my_pread64: Attempted pread on filtered fd (pipe) %d. Not supported, returning ESPIPE.",
                fd);
        errno = ESPIPE; // Illegal seek (common error for pread on pipes)
        return -1;
    } else {
        // Normal pread64
        return original_pread64(fd, buf, count, offset);
    }
}

// Hook for close
static int my_close(int fd) {
    if (!original_close) {
        TL_LOGE("my_close: original_close is null!");
        errno = EFAULT;
        return -1;
    }

    bool was_filtered = false;
    {
        std::lock_guard<std::mutex> lock(filtered_fds_mutex);
        if (filtered_fds.count(fd)) {
            TL_LOGD("my_close: Closing filtered fd %d (pipe read end)", fd);
            filtered_fds.erase(fd);
            was_filtered = true;
        }
    }

    // Always call original close, whether it was our pipe or a real fd
    return original_close(fd);
}

class TracelessModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *pApi, JNIEnv *pEnv) override {
        this->api = pApi;
        this->env = pEnv;
        TL_LOGI("Traceless v0.0.2 loaded! (Zygisk API v%d)", ZYGISK_API_VERSION);
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        preSpecialize(args);
//        preSpecialize(args);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        TL_LOGD("preServerSpecialize: system_server");
        stored_process_name = "system_server";
        on_denylist = (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST);
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        handlePostSpecialization();
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        handlePostSpecialization();
    }

    // --- Core Logic: Mount Hiding Decision ---
    static bool shouldUnmount(const MountInfo &mount) {
        const std::string &mount_point = mount.getMountPoint();
        const std::string &mount_source = mount.getMountSource();
        const std::string &fs_type = mount.getFsType();
        const MountOptions &options = mount.getMountOptions();
        const MountFlags flags = mount.getFlags();

        if (mount_point.rfind(magisk_data_path_prefix, 0) == 0) {
            TL_LOGD("shouldUnmount: YES - Mount point [%s] is in %s",
                    mount_point.c_str(), magisk_data_path_prefix.c_str());
            return true;
        }

        if (fs_type == "tmpfs" || fs_type == "overlay") {
            if (suspicious_mount_sources.count(mount_source)) {
                TL_LOGD("shouldUnmount: YES - FS type [%s] for [%s] has suspicious source [%s]",
                        fs_type.c_str(), mount_point.c_str(), mount_source.c_str());
                return true;
            }

            if (fs_type == "overlay") {
                const auto &flagmap = options.flagmap;
                for (const auto &key: {"lowerdir", "upperdir", "workdir"}) {
                    auto it = flagmap.find(key);
                    if (it != flagmap.end() && it->second.rfind(magisk_data_path_prefix, 0) == 0) {
                        TL_LOGD("shouldUnmount: YES - Overlay [%s] option \"%s\" (%s) points to %s",
                                mount_point.c_str(), key, it->second.c_str(),
                                magisk_data_path_prefix.c_str());
                        return true;
                    }
                }
            }
        }

        if ((flags & MountFlags::BIND) && mount_source.rfind(magisk_modules_path_prefix, 0) == 0) {
            TL_LOGD("shouldUnmount: YES - Bind mount [%s] originates from Magisk modules path [%s]",
                    mount_point.c_str(), mount_source.c_str());
            return true;
        }

        return false;
    }

private:
    int cfd{};
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    dev_t cdev = 0;
    ino_t cinode = 0;
    dev_t target_dev = 0;
    ino_t target_inode = 0;
    bool on_denylist = false;
    std::string stored_process_name;

    void preSpecialize(AppSpecializeArgs *args) {
        unsigned int flags = api->getFlags();
        if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto fn = [this](const std::string &lib) {
            auto di = devinoby(lib.c_str());
            if (di) {
                return *di;
            } else {
                LOGW("#[zygisk::?] devino[dl_iterate_phdr]: Failed to get device & inode for %s",
                     lib.c_str());
                LOGI("#[zygisk::?] Fallback to use `/proc/self/maps`");
                return devinobymap(lib);
            }
        };

        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            stored_process_name = process_name_chars;
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);
            on_denylist = (api->getFlags() & zygisk::StateFlag::PROCESS_ON_DENYLIST);
            TL_LOGD("preAppSpecialize: Process \"%s\" on denylist? %d",
                    stored_process_name.c_str(),
                    on_denylist);

            // If the process is on the denylist, we need to umount things
            if (on_denylist) {
                pid_t pid = getpid(), ppid = getppid();
                cfd = api->connectCompanion(); // Companion FD
                api->exemptFd(cfd);

                // Verify companion connection
                if (write(cfd, &ppid, sizeof(ppid)) != sizeof(ppid)) {
                    TL_LOGE("Communication error on PID: %d", pid);
                    close(cfd);
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                    return;
                }

                TL_LOGI("  |-> Communication: pid: %d, ppid: %d", pid, ppid);

                // Check if we can find the libc.so and libandroid_runtime.so
                std::tie(cdev, cinode) = fn("libc.so");
                if (!cdev && !cinode) {
                    TL_LOGE("Could not find dev/inode for libc.so");
                    close(cfd);
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                    return;
                } else {
                    TL_LOGI("[!] Found libc.so: dev=%u, inode=%lu", cdev, cinode);
                }

                std::tie(target_dev, target_inode) = fn("libandroid_runtime.so");
                if (!target_dev && !target_inode) {
                    TL_LOGE("Could not find dev/inode for libandroid_runtime.so");
                    close(cfd);
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                    return;
                } else {
                    TL_LOGI("[!] Found libandroid_runtime.so: dev=%u, inode=%lu", target_dev,
                            target_inode);
                }

                // Registering unshare hook
                api->pltHookRegister(target_dev, target_inode, "unshare",
                                     reinterpret_cast<void *>(reshare),
                                     reinterpret_cast<void **>(&original_unshare)
                );
                api->pltHookRegister(cdev, cinode, "fopen",
                                     reinterpret_cast<void *>(my_fopen),
                                     reinterpret_cast<void **>(&original_fopen)
                );
                api->pltHookRegister(cdev, cinode, "fgets",
                                     reinterpret_cast<void *>(my_fgets),
                                     reinterpret_cast<void **>(&original_fgets)
                );

                api->pltHookRegister(cdev, cinode, "open",
                                     reinterpret_cast<void *>(my_open),
                                     reinterpret_cast<void **>(&original_open)
                );

                api->pltHookRegister(cdev, cinode, "openat",
                                     reinterpret_cast<void *>(my_openat),
                                     reinterpret_cast<void **>(&original_openat)
                );

                api->pltHookRegister(cdev, cinode, "read",
                                     reinterpret_cast<void *>(my_read),
                                     reinterpret_cast<void **>(&original_read)
                );

                api->pltHookRegister(cdev, cinode, "pread64",
                                     reinterpret_cast<void *>(my_pread64),
                                     reinterpret_cast<void **>(&original_pread64)
                );

                api->pltHookRegister(cdev, cinode, "close",
                                     reinterpret_cast<void *>(my_close),
                                     reinterpret_cast<void **>(&original_close)
                );

                // Commit all registered PLT hooks after registration
                if (!api->pltHookCommit()) {
                    TL_LOGE("Failed to commit PLT hooks for PID %d! Hooks inactive.", pid);
                    // Reset pointers as hooks are not active
                    original_unshare = nullptr;
                    original_fopen = nullptr;
                    original_fgets = nullptr;
                    original_open = nullptr;
                    original_openat = nullptr;
                    original_read = nullptr;
                    original_pread64 = nullptr;
                    original_close = nullptr;
                    api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                    return;
                } else {
                    TL_LOGI("Successfully committed PLT hooks for PID %d.", pid);
                }

                int res = unshare(CLONE_NEWNS);
                if (res != 0) {
                    LOGE("#[zygisk::preSpecialize] unshare: %s", strerror(errno));
                    // There's nothing we can do except returning
                    close(cfd);
                    return;
                }
                res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
                if (res != 0) {
                    LOGE("#[zygisk::preSpecialize] mount(rootfs, \"/\", nullptr, MS_SLAVE | MS_REC, nullptr): returned %d: %d (%s)",
                         res, errno, strerror(errno));
                    // There's nothing we can do except returning
                    close(cfd);
                    return;
                }

                if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
                    LOGE("#[zygisk::preSpecialize] write: [-> pid]: %s", strerror(errno));
                    res = FAILURE; // Fallback to unmount from zygote
                } else if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
                    LOGE("#[zygisk::preSpecialize] read: [<- status]: %s", strerror(errno));
                    res = FAILURE; // Fallback to unmount from zygote
                } else if (res == FAILURE) {
                    LOGW("#[zygisk::preSpecialize]: Companion failed, fallback to unmount in zygote process");

                }

                close(cfd);

                if (res == FAILURE) {
                    LOGW("#[zygisk::preSpecialize]: Companion failed, fallback to unmount in zygote process");
//                    unmount(mountRules, getMountInfo()); // Unmount in current (zygote) namespace as fallback
                }
                return;
            }
        } else {
            TL_LOGE("preAppSpecialize: Failed to get process nice_name.");
            on_denylist = false;
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void handlePostSpecialization() {
        // Unhook PLT hooks
        if (original_unshare) {
            api->pltHookRegister(target_dev, target_inode, "unshare", (void *) original_unshare,
                                 nullptr);
            original_unshare = nullptr; // Clear pointer
        }
        if (original_fopen) {
            api->pltHookRegister(cdev, cinode, "fopen", (void *) original_fopen, nullptr);
            original_fopen = nullptr; // Clear pointer
        }
        if (original_fgets) {
            api->pltHookRegister(cdev, cinode, "fgets", (void *) original_fgets, nullptr);
            original_fgets = nullptr; // Clear pointer
        }
        if (original_open) {
            api->pltHookRegister(cdev, cinode, "open", (void *) original_open, nullptr);
            original_open = nullptr; // Clear pointer
        }
        if (original_openat) {
            api->pltHookRegister(cdev, cinode, "openat", (void *) original_openat, nullptr);
            original_openat = nullptr; // Clear pointer
        }
        if (original_read) {
            api->pltHookRegister(cdev, cinode, "read", (void *) original_read, nullptr);
            original_read = nullptr; // Clear pointer
        }
        if (original_pread64) {
            api->pltHookRegister(cdev, cinode, "pread64", (void *) original_pread64, nullptr);
            original_pread64 = nullptr; // Clear pointer
        }
        if (original_close) {
            api->pltHookRegister(cdev, cinode, "close", (void *) original_close, nullptr);
            original_close = nullptr; // Clear pointer
        }

        if (!api->pltHookCommit()) {
            TL_LOGE("[!] Failed to commit PLT hooks on post specialization");
        } else {
            TL_LOGI("{+} Successfully committed PLT hooks on post specialization");
        }
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
};

// --- Companion Process Implementation ---
static void companionHandler(int client_fd) {
    TL_LOGI("Companion: Handling connection on fd %d", client_fd);

    pid_t target_pid = -1;
    ssize_t bytes_read = read(client_fd, &target_pid, sizeof(target_pid));
    int read_errno = errno;

    if (close(client_fd)) {
        TL_LOGW("Companion: Failed to close client fd: %s", strerror(errno));
    }

    if (bytes_read != sizeof(target_pid)) {
        TL_LOGE("Companion: Failed to read PID (read %zd bytes, errno: %d - %s)",
                bytes_read, read_errno, strerror(read_errno));
        return;
    }

    TL_LOGI("Companion: Received target PID %d. Processing.", target_pid);

    int fork_status = forkcall([target_pid]() -> int {
        TL_LOGD("Companion: Switching to mount namespace of PID %d", target_pid);

        if (!switchnsto(target_pid)) {
            TL_LOGE("Companion: Failed to switch to namespace of PID %d", target_pid);
            return EXIT_FAILURE;
        }

        TL_LOGI("Companion: Successfully in namespace of PID %d", target_pid);
        auto mounts = getMountInfo();
        if (mounts.empty()) {
            TL_LOGW("Companion: No mounts found for PID %d", target_pid);
            return EXIT_FAILURE;
        }

        TL_LOGD("Companion: Found %zu mounts. Checking...", mounts.size());
        int unmounted_count = 0;
        int failed_count = 0;

        for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
            if (TracelessModule::shouldUnmount(*it)) {
                const char *mount_point = it->getMountPoint().c_str();
                if (umount2(mount_point, MNT_DETACH) == 0) {
                    TL_LOGI("Companion: Unmounted [%s] for PID %d", mount_point, target_pid);
                    unmounted_count++;
                } else {
                    TL_LOGW("Companion: Failed to unmount [%s] for PID %d: %s",
                            mount_point, target_pid, strerror(errno));
                    failed_count++;
                }
            }
        }

        TL_LOGI("[+] Companion: Completed for PID %d. Unmounted: %d, Failed: %d",
                target_pid, unmounted_count, failed_count);

        bool z64 = false, z32 = false;
        for (const auto &entry: std::filesystem::directory_iterator("/proc")) {
            if (!entry.is_directory())
                continue;
            std::string name = entry.path().filename();
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
            auto pid = static_cast<pid_t>(std::stoi(name));
            std::ifstream cmdline(entry.path() / "cmdline");
            std::string cmd;
            std::getline(cmdline, cmd, '\0');
            if (cmd == "zygote64") {
                std::ifstream statusFile(("/proc/" + std::to_string(pid) + "/status"));
                std::string line;
                pid_t ppid = -1;
                while (std::getline(statusFile, line)) {
                    if (line.rfind("PPid:", 0) == 0) {
                        ppid = std::stoi(line.substr(5));
                        break;
                    }
                }
                if (ppid != 1) continue;
                if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_ATTACH, %d, nullptr, nullptr): %s", pid,
                         strerror(errno));
                    continue;
                }
                waitpid(pid, nullptr, 0);
                if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEFORK) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_SETOPTIONS, %d, nullptr, PTRACE_O_TRACEFORK): %s",
                         pid, strerror(errno));
                    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                    continue;
                }
                if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_CONT, %d, nullptr, nullptr): %s", pid,
                         strerror(errno));
                    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                    continue;
                }
                while (true) {
                    int status = 0;
                    pid_t eventPid = waitpid(-1, &status, 0);
                    if (WIFSTOPPED(status)) {
                        if (status >> 16 == PTRACE_EVENT_FORK) {
                            unsigned long newChildPid = 0;
                            ptrace(PTRACE_GETEVENTMSG, eventPid, nullptr, &newChildPid);
                            LOGD("#[ps::Companion] Fork detected (%d -> fork() -> %lu)", pid,
                                 newChildPid);
                            ptrace(PTRACE_DETACH, newChildPid, nullptr, nullptr);
                            LOGD("#[ps::Companion] Detaching (%lu)", newChildPid);
                            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                            LOGD("#[ps::Companion] Detaching (%d)", pid);
                            break;
                        } else {
                            ptrace(PTRACE_CONT, eventPid, nullptr, nullptr);
                        }
                    }
                }
                z64 = true;
                continue;
            }
            if (cmd == "zygote32") {
                std::ifstream statusFile(("/proc/" + std::to_string(pid) + "/status"));
                std::string line;
                pid_t ppid = -1;
                while (std::getline(statusFile, line)) {
                    if (line.rfind("PPid:", 0) == 0) {
                        ppid = std::stoi(line.substr(5));
                        break;
                    }
                }
                if (ppid != 1) continue;
                if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_ATTACH, %d, nullptr, nullptr): %s", pid,
                         strerror(errno));
                    continue;
                }
                waitpid(pid, nullptr, 0);
                if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEFORK) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_SETOPTIONS, %d, nullptr, PTRACE_O_TRACEFORK): %s",
                         pid, strerror(errno));
                    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                    continue;
                }
                if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
                    LOGE("#[ps::Companion] ptrace(PTRACE_CONT, %d, nullptr, nullptr): %s", pid,
                         strerror(errno));
                    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                    continue;
                }
                while (true) {
                    int status = 0;
                    pid_t eventPid = waitpid(-1, &status, 0);
                    if (WIFSTOPPED(status)) {
                        if (status >> 16 == PTRACE_EVENT_FORK) {
                            unsigned long newChildPid = 0;
                            ptrace(PTRACE_GETEVENTMSG, eventPid, nullptr, &newChildPid);
                            LOGD("#[ps::Companion] Fork detected (%d -> fork() -> %lu)", pid,
                                 newChildPid);
                            ptrace(PTRACE_DETACH, newChildPid, nullptr, nullptr);
                            LOGD("#[ps::Companion] Detaching (%lu)", newChildPid);
                            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
                            LOGD("#[ps::Companion] Detaching (%d)", pid);
                            break;
                        } else {
                            ptrace(PTRACE_CONT, eventPid, nullptr, nullptr);
                        }
                    }
                }
                z32 = true;
                continue;
            }
        }
        return z64 || z32;

        return EXIT_SUCCESS;
    });

    if (fork_status != EXIT_SUCCESS) {
        TL_LOGE("Companion: Unmount task failed for PID %d (status: %d)",
                target_pid, fork_status);
    }
}

// --- Zygisk Registration ---
REGISTER_ZYGISK_MODULE(TracelessModule)

REGISTER_ZYGISK_COMPANION(companionHandler)