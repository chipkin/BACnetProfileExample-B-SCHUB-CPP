// SPDX-License-Identifier: CC0-1.0
// Public-domain example code (CC0) - see LICENSE.
//
// cert_layout.cpp - see cert_layout.h.

#include "cert_layout.h"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

namespace CertLayout {
namespace {

std::string Join(const fs::path& dir, const std::string& relative) {
    return (dir / fs::path(relative)).generic_string();
}

// "device-389022" -> 389022. False if `name` isn't device-<0..4194302>.
bool ParseDeviceFolder(const std::string& name, uint32_t* instance) {
    const std::string prefix = "device-";
    if (name.compare(0, prefix.size(), prefix) != 0 || name.size() == prefix.size()) {
        return false;
    }
    const std::string digits = name.substr(prefix.size());
    if (digits.find_first_not_of("0123456789") != std::string::npos || digits.size() > 7) {
        return false;
    }
    errno = 0;
    const unsigned long value = std::strtoul(digits.c_str(), nullptr, 10);
    if (errno == ERANGE || value > 4194302UL) {
        return false;
    }
    *instance = (uint32_t)value;
    return true;
}

// Every cert1/device-*/port-*/ folder with a hub/ marker, as
// (relative port folder, device instance).
std::vector<std::pair<std::string, uint32_t>> FindHubPorts(const fs::path& certDir) {
    std::vector<std::pair<std::string, uint32_t>> found;
    std::error_code ec;
    for (const auto& device : fs::directory_iterator(certDir / "cert1", ec)) {
        uint32_t instance = 0;
        if (!device.is_directory() || !ParseDeviceFolder(device.path().filename().string(), &instance)) {
            continue;
        }
        std::error_code portEc;
        for (const auto& port : fs::directory_iterator(device.path(), portEc)) {
            const std::string name = port.path().filename().string();
            if (port.is_directory() && name.compare(0, 5, "port-") == 0 && fs::is_directory(port.path() / "hub")) {
                found.emplace_back("cert1/" + device.path().filename().string() + "/" + name, instance);
            }
        }
    }
    return found;
}

void FillCari(HubCertPaths* p, const fs::path& dir, const std::string& portFolder, uint32_t instance) {
    p->certDir = dir.generic_string();
    p->trustedIssuers = Join(dir, "trusted-issuers.pem");
    p->revocationList = Join(dir, "issuer-crl.pem");
    p->portFolder = portFolder;
    p->folderDeviceInstance = instance;
    const std::string name = HUB_FILE_NAME;
    p->operationalCertificate = Join(dir, portFolder + "/opr-" + name + ".pem");
    p->certificateSigningRequest = Join(dir, portFolder + "/csr-" + name + ".pem");
    p->privateKey = Join(dir, portFolder + "/key-" + name + ".pem");
    p->issuerCertificate1 = Join(dir, "cert1/issuer/iss-1.pem");
    p->issuerCertificate2 = Join(dir, "cert1/issuer/iss-2.pem");
    p->pendingPrivateKey = Join(dir, "key-" + name + "-pending.pem");
}

// The paths a NEW set uses: cert1/device-<instance>/port-2.
HubCertPaths NewHubCertPaths(const std::string& certDir, uint32_t deviceInstance) {
    HubCertPaths p;
    FillCari(&p, fs::path(certDir), "cert1/device-" + std::to_string(deviceInstance) + "/port-" + HUB_PORT_ID,
             deviceInstance);
    return p;
}

}  // namespace

HubCertPaths ResolveHubCertPaths(const std::string& certDirArg, uint32_t deviceInstance) {
    const fs::path dir(certDirArg);
    std::error_code ec;

    if (!fs::is_directory(dir / "cert1", ec)) {
        return NewHubCertPaths(certDirArg, deviceInstance);  // nothing yet
    }
    const std::vector<std::pair<std::string, uint32_t>> ports = FindHubPorts(dir);
    if (ports.empty()) {
        return NewHubCertPaths(certDirArg, deviceInstance);
    }
    size_t chosen = 0;
    for (size_t i = 0; i < ports.size(); ++i) {
        if (ports[i].second == deviceInstance) {
            chosen = i;
        }
    }
    HubCertPaths p;
    FillCari(&p, dir, ports[chosen].first, ports[chosen].second);
    if (ports[chosen].second != deviceInstance) {
        p.note = "the certificate folder " + ports[chosen].first + " is for device instance " +
                 std::to_string(ports[chosen].second) + ", but this device is " + std::to_string(deviceInstance) +
                 "; using it anyway (rename the folder to device-" + std::to_string(deviceInstance) +
                 " to match)";
    }
    if (ports.size() > 1) {
        p.note += std::string(p.note.empty() ? "" : "; ") + std::to_string(ports.size()) +
                  " hub port folders found under cert1/, using " + ports[chosen].first;
    }
    return p;
}

std::string RelativeTo(const std::string& base, const std::string& path) {
    std::error_code ec;
    const fs::path rel = fs::relative(fs::path(path), fs::path(base), ec);
    if (ec || rel.empty() || rel.generic_string().compare(0, 2, "..") == 0) {
        return fs::path(path).generic_string();
    }
    return rel.generic_string();
}

}  // namespace CertLayout
