/*
 * This file includes modifications derived from The Android Open Source Project,
 * which is licensed under the Apache License, Version 2.0 (the "License").
 * These modifications are provided under the same License terms as the original work.
 *
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

#include <dirent.h>
#include <cinttypes>
#include <sys/stat.h>

typedef const std::function<void(std::string)>& fail_fn_t;

// Returns the set of file descriptors currently open by the process.
std::unique_ptr<std::set<int>> GetOpenFds(fail_fn_t fail_fn);

// Keeps track of all relevant information (flags, offset etc.) of an
// open zygote file descriptor.
class FileDescriptorInfo {
public:
	// Create a FileDescriptorInfo for a given file descriptor.
	static std::unique_ptr<FileDescriptorInfo> CreateFromFd(int fd, fail_fn_t fail_fn);
	// Checks whether the file descriptor associated with this object refers to
	// the same description.
	bool RefersToSameFile() const;
	bool GetSocketName(std::string* result);

    // Reopens non-socket FDs or detaches socket FDs (to /dev/null).
    // If prefer_detach_to_dev_null is true for non-sockets, they are also detached.
	void ReopenOrDetach(fail_fn_t fail_fn, bool prefer_detach_to_dev_null) const;
    
    // Detaches the FD by redirecting it to /dev/null.
    void Detach(fail_fn_t fail_fn) const;


	const int fd;
	const struct stat stat;
	const std::string file_path;
	const int open_flags;
	const int fd_flags;
	const int fs_flags;
	const off_t offset;
	const bool is_sock;
private:
	// Constructs for sockets.
	explicit FileDescriptorInfo(int fd);
	// Constructs for non-socket file descriptors.
	FileDescriptorInfo(struct stat stat, const std::string& file_path, int fd, int open_flags,
					   int fd_flags, int fs_flags, off_t offset);

	FileDescriptorInfo(const FileDescriptorInfo&) = delete;
	void operator=(const FileDescriptorInfo&) = delete;
};
