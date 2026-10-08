// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cari.cpp - see cari.h.

#include "cari.h"

#include <zlib.h>

#include <stdio.h>
#include <time.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace Cari {
namespace {

// --- little-endian helpers ---------------------------------------------------

uint16_t Get16(const std::string& b, size_t at) {
    return (uint16_t)((uint8_t)b[at] | ((uint8_t)b[at + 1] << 8));
}
uint32_t Get32(const std::string& b, size_t at) {
    return (uint32_t)Get16(b, at) | ((uint32_t)Get16(b, at + 2) << 16);
}
void Put16(std::string* b, uint16_t v) {
    b->push_back((char)(v & 0xFF));
    b->push_back((char)(v >> 8));
}
void Put32(std::string* b, uint32_t v) {
    Put16(b, (uint16_t)(v & 0xFFFF));
    Put16(b, (uint16_t)(v >> 16));
}

const uint32_t LOCAL_HEADER_SIG = 0x04034b50;
const uint32_t CENTRAL_HEADER_SIG = 0x02014b50;
const uint32_t END_OF_CENTRAL_DIR_SIG = 0x06054b50;

bool Inflate(const std::string& in, size_t expected, std::string* out) {
    out->assign(expected, '\0');
    z_stream s;
    std::memset(&s, 0, sizeof(s));
    if (inflateInit2(&s, -MAX_WBITS) != Z_OK) {  // raw deflate, as zip stores it
        return false;
    }
    s.next_in = (Bytef*)in.data();
    s.avail_in = (uInt)in.size();
    s.next_out = (Bytef*)&(*out)[0];
    s.avail_out = (uInt)expected;
    const int rc = inflate(&s, Z_FINISH);
    const bool ok = rc == Z_STREAM_END && s.total_out == expected;
    inflateEnd(&s);
    return ok || (expected == 0 && rc == Z_BUF_ERROR);
}

std::string Deflate(const std::string& in) {
    z_stream s;
    std::memset(&s, 0, sizeof(s));
    deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    std::string out(deflateBound(&s, (uLong)in.size()), '\0');
    s.next_in = (Bytef*)in.data();
    s.avail_in = (uInt)in.size();
    s.next_out = (Bytef*)&out[0];
    s.avail_out = (uInt)out.size();
    deflate(&s, Z_FINISH);
    out.resize(s.total_out);
    deflateEnd(&s);
    return out;
}

// A path a zip may name: relative, '/'-separated, no "." or ".." parts, no
// backslash, colon or control characters.
bool IsSafeZipPath(const std::string& path) {
    if (path.empty() || path[0] == '/' || path.find('\\') != std::string::npos ||
        path.find(':') != std::string::npos) {
        return false;
    }
    std::stringstream parts(path);
    std::string part;
    while (std::getline(parts, part, '/')) {
        if (part.empty() || part == "." || part == "..") {
            return false;
        }
        for (const char c : part) {
            if ((unsigned char)c < 0x20 || c == 0x7F) {
                return false;
            }
        }
    }
    return true;
}

std::vector<std::string> Split(const std::string& path) {
    std::vector<std::string> parts;
    std::stringstream in(path);
    std::string part;
    while (std::getline(in, part, '/')) {
        parts.push_back(part);
    }
    return parts;
}

bool StartsWith(const std::string& s, const char* prefix) {
    return s.compare(0, std::strlen(prefix), prefix) == 0;
}
bool EndsWith(const std::string& s, const char* suffix) {
    const size_t n = std::strlen(suffix);
    return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

// "device-12" -> 12, if it is a legal device folder name.
bool DeviceInstance(const std::string& folder, uint32_t* instance) {
    if (!StartsWith(folder, "device-") || folder.size() == 7 || folder.size() > 14) {
        return false;
    }
    const std::string digits = folder.substr(7);
    if (digits.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    const unsigned long v = std::strtoul(digits.c_str(), nullptr, 10);
    if (v > 4194302UL) {
        return false;
    }
    *instance = (uint32_t)v;
    return true;
}

// "csr-abc.pem" with prefix "csr-" -> "abc", if legal.
bool FileName(const std::string& file, const char* prefix, std::string* name) {
    if (!StartsWith(file, prefix) || !EndsWith(file, ".pem")) {
        return false;
    }
    *name = file.substr(std::strlen(prefix), file.size() - std::strlen(prefix) - 4);
    return IsValidName(*name);
}

}  // namespace

// --- Tree ----------------------------------------------------------------------

void Tree::AddFolder(const std::string& path) {
    std::string partial;
    for (const std::string& part : Split(path)) {
        partial += (partial.empty() ? "" : "/") + part;
        folders.insert(partial);
    }
}

void Tree::AddFile(const std::string& path, const std::string& bytes) {
    const size_t slash = path.rfind('/');
    if (slash != std::string::npos) {
        AddFolder(path.substr(0, slash));
    }
    files[path] = bytes;
}

void Tree::Remove(const std::string& path) {
    files.erase(path);
}

bool IsValidName(const std::string& text) {
    if (text.empty() || text.size() > 128) {
        return false;
    }
    for (const char c : text) {
        const unsigned char u = (unsigned char)c;
        if (u < 0x20 || u == 0x7F || std::strchr("<>:\"/\\|?*", c) != nullptr) {
            return false;
        }
    }
    return true;
}

// --- zip -------------------------------------------------------------------------

bool ReadZip(const std::string& zip, Tree* out, std::string* error) {
    *out = Tree();
    if (zip.size() > MAX_ZIP_BYTES) {
        *error = "the file is " + std::to_string(zip.size()) + " bytes; the limit is " +
                 std::to_string(MAX_ZIP_BYTES);
        return false;
    }
    if (zip.size() < 22 || Get32(zip, 0) != LOCAL_HEADER_SIG) {
        *error = "not a zip file (a CARI file is a .zip with a cert1/ folder in it)";
        return false;
    }
    // The end-of-central-directory record: within the last 64 KiB + 22 bytes.
    size_t eocd = std::string::npos;
    const size_t lowest = zip.size() > 65557 ? zip.size() - 65557 : 0;
    for (size_t at = zip.size() - 22 + 1; at-- > lowest;) {
        if (Get32(zip, at) == END_OF_CENTRAL_DIR_SIG) {
            eocd = at;
            break;
        }
    }
    if (eocd == std::string::npos) {
        *error = "the zip file is damaged (no end-of-central-directory record)";
        return false;
    }
    const uint16_t entries = Get16(zip, eocd + 10);
    const uint32_t cdSize = Get32(zip, eocd + 12);
    const uint32_t cdOffset = Get32(zip, eocd + 16);
    if (Get16(zip, eocd + 4) != 0 || Get16(zip, eocd + 6) != 0 || entries != Get16(zip, eocd + 8)) {
        *error = "multi-part zip files are not supported";
        return false;
    }
    if (entries > MAX_ENTRIES) {
        *error = "the zip has " + std::to_string(entries) + " entries; the limit is " + std::to_string(MAX_ENTRIES);
        return false;
    }
    if ((uint64_t)cdOffset + cdSize > eocd) {
        *error = "the zip file is damaged (central directory out of range)";
        return false;
    }
    size_t total = 0;
    size_t at = cdOffset;
    for (uint16_t i = 0; i < entries; ++i) {
        if (at + 46 > eocd || Get32(zip, at) != CENTRAL_HEADER_SIG) {
            *error = "the zip file is damaged (central directory entry " + std::to_string(i) + ")";
            return false;
        }
        const uint16_t flags = Get16(zip, at + 8);
        const uint16_t method = Get16(zip, at + 10);
        const uint32_t crc = Get32(zip, at + 16);
        const uint32_t csize = Get32(zip, at + 20);
        const uint32_t usize = Get32(zip, at + 24);
        const uint16_t nameLen = Get16(zip, at + 28);
        const uint16_t extraLen = Get16(zip, at + 30);
        const uint16_t commentLen = Get16(zip, at + 32);
        const uint32_t localOffset = Get32(zip, at + 42);
        if (at + 46 + nameLen > eocd) {
            *error = "the zip file is damaged (entry name out of range)";
            return false;
        }
        std::string name = zip.substr(at + 46, nameLen);
        at += 46 + nameLen + extraLen + commentLen;

        if ((flags & 0x0001) != 0) {
            *error = "\"" + name + "\" is encrypted; CARI files are not";
            return false;
        }
        if (csize == 0xFFFFFFFF || usize == 0xFFFFFFFF || localOffset == 0xFFFFFFFF) {
            *error = "zip64 files are not supported";
            return false;
        }
        if (method != 0 && method != 8) {
            *error = "\"" + name + "\" uses compression method " + std::to_string(method) +
                     "; only stored (0) and deflate (8) are supported";
            return false;
        }
        const bool isFolder = !name.empty() && name.back() == '/';
        if (isFolder) {
            name.pop_back();
        }
        if (!IsSafeZipPath(name)) {
            *error = "unsafe path in the zip: \"" + name + "\"";
            return false;
        }
        if (isFolder) {
            out->AddFolder(name);
            continue;
        }
        total += usize;
        if (total > MAX_TOTAL_UNCOMPRESSED) {
            *error = "the zip unpacks to more than " + std::to_string(MAX_TOTAL_UNCOMPRESSED) + " bytes";
            return false;
        }
        if ((uint64_t)localOffset + 30 > zip.size() || Get32(zip, localOffset) != LOCAL_HEADER_SIG) {
            *error = "the zip file is damaged (local header for \"" + name + "\")";
            return false;
        }
        const size_t dataAt = localOffset + 30 + Get16(zip, localOffset + 26) + Get16(zip, localOffset + 28);
        if ((uint64_t)dataAt + csize > zip.size()) {
            *error = "the zip file is damaged (data for \"" + name + "\" out of range)";
            return false;
        }
        const std::string compressed = zip.substr(dataAt, csize);
        std::string data;
        if (method == 0) {
            if (csize != usize) {
                *error = "the zip file is damaged (size of \"" + name + "\")";
                return false;
            }
            data = compressed;
        } else if (!Inflate(compressed, usize, &data)) {
            *error = "could not decompress \"" + name + "\"";
            return false;
        }
        if (crc32(0L, (const Bytef*)data.data(), (uInt)data.size()) != crc) {
            *error = "\"" + name + "\" is damaged (CRC mismatch)";
            return false;
        }
        if (out->files.count(name) != 0) {
            *error = "\"" + name + "\" appears twice in the zip";
            return false;
        }
        out->AddFile(name, data);
    }
    return true;
}

std::string WriteZip(const Tree& tree) {
    // Every folder (with a trailing '/') then every file, in path order, so the
    // zip lists cert1/ first.
    struct Entry {
        std::string name;
        std::string data;
    };
    std::vector<Entry> entries;
    for (const std::string& folder : tree.folders) {
        entries.push_back({folder + "/", std::string()});
    }
    for (const auto& file : tree.files) {
        entries.push_back({file.first, file.second});
    }

    // DOS date/time of "now", for every entry.
    const time_t now = time(nullptr);
    struct tm t;
#if defined(_WIN32)
    localtime_s(&t, &now);
#else
    localtime_r(&now, &t);
#endif
    const uint16_t dosTime = (uint16_t)((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec / 2));
    const uint16_t dosDate = (uint16_t)(((t.tm_year - 80) << 9) | ((t.tm_mon + 1) << 5) | t.tm_mday);

    std::string zip;
    std::string central;
    for (const Entry& e : entries) {
        const bool isFolder = e.name.back() == '/';
        const std::string body = isFolder ? std::string() : Deflate(e.data);
        const uint16_t method = isFolder ? 0 : 8;
        const uint32_t crc = (uint32_t)crc32(0L, (const Bytef*)e.data.data(), (uInt)e.data.size());
        const uint32_t offset = (uint32_t)zip.size();

        Put32(&zip, LOCAL_HEADER_SIG);
        Put16(&zip, 20);       // version needed
        Put16(&zip, 0x0800);   // UTF-8 names
        Put16(&zip, method);
        Put16(&zip, dosTime);
        Put16(&zip, dosDate);
        Put32(&zip, crc);
        Put32(&zip, (uint32_t)body.size());
        Put32(&zip, (uint32_t)e.data.size());
        Put16(&zip, (uint16_t)e.name.size());
        Put16(&zip, 0);
        zip += e.name;
        zip += body;

        Put32(&central, CENTRAL_HEADER_SIG);
        Put16(&central, 20);   // version made by
        Put16(&central, 20);
        Put16(&central, 0x0800);
        Put16(&central, method);
        Put16(&central, dosTime);
        Put16(&central, dosDate);
        Put32(&central, crc);
        Put32(&central, (uint32_t)body.size());
        Put32(&central, (uint32_t)e.data.size());
        Put16(&central, (uint16_t)e.name.size());
        Put16(&central, 0);    // extra
        Put16(&central, 0);    // comment
        Put16(&central, 0);    // disk
        Put16(&central, 0);    // internal attributes
        Put32(&central, isFolder ? 0x10 : 0);  // external: MS-DOS directory bit
        Put32(&central, offset);
        central += e.name;
    }
    const uint32_t cdOffset = (uint32_t)zip.size();
    zip += central;
    Put32(&zip, END_OF_CENTRAL_DIR_SIG);
    Put16(&zip, 0);
    Put16(&zip, 0);
    Put16(&zip, (uint16_t)entries.size());
    Put16(&zip, (uint16_t)entries.size());
    Put32(&zip, (uint32_t)central.size());
    Put32(&zip, cdOffset);
    Put16(&zip, 0);
    return zip;
}

// --- CARI rules ---------------------------------------------------------------------

bool Validate(const Tree& tree, bool response, std::vector<std::string>* problems) {
    problems->clear();
    auto problem = [problems](const std::string& path, const std::string& why) {
        problems->push_back(path + ": " + why);
    };
    bool sawDevice = false;
    std::set<std::string> devicesWithPort;

    for (const std::string& folder : tree.folders) {
        const std::vector<std::string> p = Split(folder);
        uint32_t instance = 0;
        if (p[0] != "cert1") {
            problem(folder, "everything must be inside the cert1/ folder");
        } else if (p.size() == 1) {
            // cert1 itself
        } else if (p.size() == 2 && p[1] == "issuer") {
            if (!response) {
                problem(folder, "issuer/ belongs in a response, not a request");
            }
        } else if (!DeviceInstance(p[1], &instance)) {
            problem(folder, "a folder in cert1/ must be device-<instance> (0..4194302) or issuer");
        } else if (p.size() == 2) {
            sawDevice = true;
        } else if (p.size() == 3 && p[2] == "router") {
            // empty marker: the device routes between BACnet/SC networks
        } else if (!StartsWith(p[2], "port-") || !IsValidName(p[2].substr(5))) {
            problem(folder, "a folder in a device folder must be router or port-<id> (no < > : \" / \\ | ? *)");
        } else if (p.size() == 3) {
            devicesWithPort.insert(p[1]);
        } else if (p.size() == 4 && p[3] == "hub") {
            // empty marker: this port is a hub function
        } else {
            problem(folder, "unexpected folder (a port folder may only contain hub/)");
        }
    }

    for (const auto& file : tree.files) {
        const std::string& path = file.first;
        const size_t size = file.second.size();
        const std::vector<std::string> p = Split(path);
        std::string name;
        uint32_t instance = 0;
        if (p[0] != "cert1" || p.size() < 2) {
            problem(path, "everything must be inside the cert1/ folder");
        } else if (p.size() == 2) {
            if (p[1] == "vendor-data") {
                if (size > MAX_VENDOR_DATA) problem(path, "larger than 1 MB");
            } else if (p[1] == "request-notes.txt") {
                if (size > MAX_NOTES) problem(path, "larger than 10 kB");
            } else if (response && (p[1] == "response-notes.txt" || p[1] == "errors.txt")) {
                if (size > MAX_NOTES && p[1] != "errors.txt") problem(path, "larger than 10 kB");
            } else {
                problem(path, "not a CARI file name (cert1/ may hold vendor-data, request-notes.txt" +
                              std::string(response ? ", response-notes.txt, errors.txt" : "") + ")");
            }
        } else if (p.size() == 3 && p[1] == "issuer") {
            if (!response) {
                problem(path, "issuer files belong in a response, not a request");
            } else if (p[2] != "iss-1.pem" && p[2] != "iss-2.pem") {
                problem(path, "the issuer folder may only hold iss-1.pem and iss-2.pem");
            }
        } else if (p.size() == 4 && DeviceInstance(p[1], &instance) && StartsWith(p[2], "port-")) {
            const bool known = FileName(p[3], "csr-", &name) || FileName(p[3], "key-", &name) ||
                               (response && FileName(p[3], "opr-", &name));
            if (!known) {
                problem(path, std::string("a port folder may only hold csr-<name>.pem, key-<name>.pem") +
                              (response ? ", opr-<name>.pem" : "") + " (no < > : \" / \\ | ? * in <name>)");
            } else if (size > MAX_PEM) {
                problem(path, "larger than 64 kB");
            }
        } else {
            problem(path, "not a place a CARI file can be");
        }
    }

    if (!sawDevice) {
        problems->push_back("cert1/: there is no device-<instance> folder");
    }
    for (const std::string& folder : tree.folders) {
        const std::vector<std::string> p = Split(folder);
        uint32_t instance = 0;
        if (p.size() == 2 && DeviceInstance(p[1], &instance) && devicesWithPort.count(p[1]) == 0) {
            problem(folder, "a device folder must contain at least one port-<id> folder");
        }
    }
    return problems->empty();
}

std::vector<CsrEntry> ListCsrs(const Tree& tree) {
    std::vector<CsrEntry> csrs;
    for (const auto& file : tree.files) {
        const std::vector<std::string> p = Split(file.first);
        CsrEntry e;
        if (p.size() != 4 || p[0] != "cert1" || !DeviceInstance(p[1], &e.deviceInstance) ||
            !StartsWith(p[2], "port-") || !FileName(p[3], "csr-", &e.name)) {
            continue;
        }
        e.deviceFolder = p[1];
        e.portFolder = p[2];
        const std::string port = "cert1/" + p[1] + "/" + p[2];
        e.csrPath = file.first;
        e.oprPath = port + "/opr-" + e.name + ".pem";
        e.keyPath = tree.Has(port + "/key-" + e.name + ".pem") ? port + "/key-" + e.name + ".pem" : std::string();
        e.isHubPort = tree.folders.count(port + "/hub") != 0;
        e.isRouter = tree.folders.count("cert1/" + p[1] + "/router") != 0;
        csrs.push_back(e);
    }
    return csrs;
}

// --- disk ----------------------------------------------------------------------------

bool WriteToDir(const Tree& tree, const std::string& baseDir, std::string* error) {
    const fs::path base(baseDir);
    std::error_code ec;
    for (const std::string& folder : tree.folders) {
        if (!IsSafeZipPath(folder)) {
            *error = "unsafe folder \"" + folder + "\"";
            return false;
        }
        fs::create_directories(base / fs::path(folder), ec);
    }
    for (const auto& file : tree.files) {
        if (!IsSafeZipPath(file.first)) {
            *error = "unsafe path \"" + file.first + "\"";
            return false;
        }
        const fs::path path = base / fs::path(file.first);
        fs::create_directories(path.parent_path(), ec);
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            *error = "could not write \"" + path.string() + "\"";
            return false;
        }
        f.write(file.second.data(), (std::streamsize)file.second.size());
        f.close();
        if (path.filename().string().compare(0, 4, "key-") == 0) {
            fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
        }
    }
    return true;
}

bool ReadFromDir(const std::string& baseDir, Tree* out, std::string* error) {
    *out = Tree();
    const fs::path base(baseDir);
    std::error_code ec;
    if (!fs::is_directory(base / "cert1", ec)) {
        *error = "no cert1/ folder in \"" + baseDir + "\"";
        return false;
    }
    out->AddFolder("cert1");
    for (auto it = fs::recursive_directory_iterator(base / "cert1", ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        const std::string rel = fs::relative(it->path(), base, ec).generic_string();
        if (it->is_directory()) {
            out->AddFolder(rel);
        } else if (it->is_regular_file()) {
            std::ifstream f(it->path(), std::ios::binary);
            std::stringstream bytes;
            bytes << f.rdbuf();
            out->AddFile(rel, bytes.str());
        }
    }
    return true;
}

}  // namespace Cari
