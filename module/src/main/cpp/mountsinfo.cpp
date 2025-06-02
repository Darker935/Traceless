#pragma once

#include <string>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <type_traits>
#include <algorithm>
#include <sys/types.h>
#include <sys/sysmacros.h>

enum class MountFlags : uint64_t {
	RO         = 1ull << 0,
	RW         = 1ull << 1,
	NOEXEC     = 1ull << 2,
	EXEC       = 1ull << 3,
	NOSUID     = 1ull << 4,
	SUID       = 1ull << 5,
	NODEV      = 1ull << 6,
	DEV        = 1ull << 7,
	RELATIME   = 1ull << 8,
	NORELATIME = 1ull << 9,
	STRICTATIME= 1ull << 10,
	NOATIME    = 1ull << 11,
	ATIME      = 1ull << 12,
	DIRSYNC    = 1ull << 13,
	SYNC       = 1ull << 14,
	MANDLOCK   = 1ull << 15,
	NODIRATIME = 1ull << 16,
	LAZYTIME   = 1ull << 17,
	SECLABEL   = 1ull << 18,
	INDEX      = 1ull << 19,
	NOINDEX    = 1ull << 20,
	METACOPY   = 1ull << 21,
	NOMETACOPY = 1ull << 22,
	BIND       = 1ull << 23,
	RPRIVATE   = 1ull << 24,
	RSHARED    = 1ull << 25,
	RSLAVE     = 1ull << 26,
	PRIVATE    = 1ull << 27,
	SHARED     = 1ull << 28,
	SLAVE      = 1ull << 29,
	REC        = 1ull << 30,
	REMOUNT    = 1ull << 31,
	NOSYMFOLLOW= 1ull << 32
};


inline MountFlags operator|(MountFlags a, MountFlags b) {
	return static_cast<MountFlags>(
			static_cast<std::underlying_type_t<MountFlags>>(a) |
			static_cast<std::underlying_type_t<MountFlags>>(b)
	);
}

inline MountFlags& operator|=(MountFlags& a, MountFlags b) {
	a = a | b;
	return a;
}

inline bool operator&(MountFlags a, MountFlags b) {
	return
			static_cast<std::underlying_type_t<MountFlags>>(a) &
			static_cast<std::underlying_type_t<MountFlags>>(b);
}

enum class PropagationType {
	PRIVATE,
	SHARED,
	SLAVE,
	UNBINDABLE,
	UNKNOWN
};

struct MountPropagation {
	PropagationType type = PropagationType::UNKNOWN;
	int id = -1;
};

static const std::unordered_map<std::string, MountFlags> mountFlags = {
		{"ro", MountFlags::RO}, {"rw", MountFlags::RW}, {"noexec", MountFlags::NOEXEC},
		{"exec", MountFlags::EXEC}, {"nosuid", MountFlags::NOSUID}, {"suid", MountFlags::SUID},
		{"nodev", MountFlags::NODEV}, {"dev", MountFlags::DEV}, {"relatime", MountFlags::RELATIME},
		{"norelatime", MountFlags::NORELATIME}, {"strictatime", MountFlags::STRICTATIME},
		{"noatime", MountFlags::NOATIME}, {"atime", MountFlags::ATIME}, {"dirsync", MountFlags::DIRSYNC},
		{"sync", MountFlags::SYNC}, {"mand", MountFlags::MANDLOCK}, {"nodiratime", MountFlags::NODIRATIME},
		{"lazytime", MountFlags::LAZYTIME}, {"seclabel", MountFlags::SECLABEL}, {"index", MountFlags::INDEX},
		{"noindex", MountFlags::NOINDEX}, {"metacopy", MountFlags::METACOPY},
		{"nometacopy", MountFlags::NOMETACOPY}, {"bind", MountFlags::BIND},
		{"rprivate", MountFlags::RPRIVATE}, {"rshared", MountFlags::RSHARED},
		{"rslave", MountFlags::RSLAVE}, {"private", MountFlags::PRIVATE},
		{"shared", MountFlags::SHARED}, {"slave", MountFlags::SLAVE},
		{"rec", MountFlags::REC}, {"remount", MountFlags::REMOUNT},
		{"nosymfollow", MountFlags::NOSYMFOLLOW}
};

struct MountOptions {
	MountFlags flags = MountFlags(0);
	std::unordered_map<std::string, std::string> flagmap;

	void parse(const std::string& str) {
		std::istringstream s(str);
		std::string opt;
		while (std::getline(s, opt, ',')) {
			auto it = mountFlags.find(opt);
			if (it != mountFlags.end()) {
				flags |= it->second;
			} else {
				size_t eq = opt.find('=');
				if (eq != std::string::npos) {
					flagmap[opt.substr(0, eq)] = opt.substr(eq + 1);
				}
			}
		}
	}
};

class MountInfo {
public:
	explicit MountInfo(const std::string& line) {
		std::istringstream ss(line);
		std::vector<std::string> parts;
		std::string token;
		while (ss >> token)
			parts.push_back(token);
		auto it = std::find(parts.begin(), parts.end(), std::string("-"));
		if (it == parts.end() || std::distance(parts.begin(), it) < 6)
			return;
		size_t sep_idx = std::distance(parts.begin(), it);
		mnt_id = std::stoi(parts[0]);
		mnt_parent_id = std::stoi(parts[1]);
		parseMajorMinor(parts[2]);
		root = parts[3];
		mnt_pnt = parts[4];
		parseFlags(parts[5]);
		for (size_t i = 6; i < sep_idx; ++i)
			parsePropagation(parts[i]);
		fs_type = parts[sep_idx + 1];
		mnt_src = parts[sep_idx + 2];
		parseOptions(parts[sep_idx + 3]);
	}

	~MountInfo() = default;

	[[nodiscard]] int getMountId() const { return mnt_id; }
	[[nodiscard]] int getParentId() const { return mnt_parent_id; }
	[[nodiscard]] dev_t getDev() const { return dev; }
	[[nodiscard]] const std::string& getRoot() const { return root; }
	[[nodiscard]] const std::string& getMountPoint() const { return mnt_pnt; }
	[[nodiscard]] MountFlags getFlags() const { return mnt_flags; }
	[[nodiscard]] const MountPropagation& getPropagation() const { return propagation; }
	[[nodiscard]] const std::string& getFsType() const { return fs_type; }
	[[nodiscard]] const std::string& getMountSource() const { return mnt_src; }
	[[nodiscard]] const MountOptions& getMountOptions() const { return mnt_opts; }

private:
	int mnt_id;
	int mnt_parent_id;
	dev_t dev = 0;
	std::string root;
	std::string mnt_pnt;
	MountFlags mnt_flags = MountFlags(0);
	MountPropagation propagation;
	std::string fs_type;
	std::string mnt_src;
	MountOptions mnt_opts;

	void parseFlags(const std::string& str) {
		std::istringstream s(str);
		std::string opt;
		while (std::getline(s, opt, ',')) {
			auto it = mountFlags.find(opt);
			if (it != mountFlags.end())
				mnt_flags |= it->second;
		}
	}

	void parsePropagation(const std::string& pg) {
		if (pg.find("master:") == 0) {
			propagation.type = PropagationType::SLAVE;
			propagation.id = std::stoi(pg.substr(7));
		} else if (pg.find("shared:") == 0) {
			propagation.type = PropagationType::SHARED;
			propagation.id = std::stoi(pg.substr(7));
		} else if (pg == "unbindable") {
			propagation.type = PropagationType::UNBINDABLE;
		} else if (pg == "private") {
			propagation.type = PropagationType::PRIVATE;
		}
	}

	void parseOptions(const std::string& opt) {
		mnt_opts.parse(opt);
	}

	void parseMajorMinor(const std::string& mmstr) {
		size_t sep = mmstr.find(':');
		if (sep != std::string::npos) {
			int major = std::stoi(mmstr.substr(0, sep));
			int minor = std::stoi(mmstr.substr(sep + 1));
			dev = makedev(major, minor);
		} else {
			dev = 0;
		}
	}
};

class MountRootResolver {
private:
	std::unordered_map<dev_t, std::string> dmm;

public:
	explicit MountRootResolver(const std::vector<MountInfo>& mounts) {
		for (const auto& mount : mounts) {
			if (mount.getRoot() == "/") {
				dmm[mount.getDev()] = mount.getMountPoint();
			}
		}
	}

	~MountRootResolver() = default;

	std::string resolveRoot(const MountInfo& mount) {
		auto dev = mount.getDev();
		auto it = dmm.find(dev);
		if (it != dmm.end()) {
			if (it->second != "/")
				return it->second + mount.getRoot();
		}
		return mount.getRoot();
	}
};

inline std::vector<MountInfo> getMountInfo(const std::string& path = "/proc/self/mountinfo") {
	std::ifstream mi(path);
	std::vector<MountInfo> mounts;
	std::string line;
	if (!mi.is_open())
		return mounts;
	while (std::getline(mi, line)) {
		MountInfo mountInfo(line);
		mounts.emplace_back(std::move(mountInfo));
	}
	mi.close();
	return mounts;
}