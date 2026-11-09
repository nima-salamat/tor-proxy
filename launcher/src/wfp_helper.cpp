#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
const GUID kProviderKey = {
    0x6c2b73d1, 0x95d8, 0x4f2b, {0xa8, 0x61, 0x7d, 0x32, 0x91, 0xe4, 0xb5, 0x10}
};
const GUID kSubLayerKey = {
    0x8d6f1c24, 0x3e7a, 0x4b91, {0x9c, 0x52, 0x44, 0x18, 0xf0, 0xd2, 0xa7, 0x63}
};

std::wstring errorMessage(const wchar_t* operation, DWORD status) {
    wchar_t* systemText = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, status, 0, reinterpret_cast<LPWSTR>(&systemText), 0, nullptr);
    std::wstringstream stream;
    stream << operation << L" failed (0x" << std::hex << std::uppercase << status << L")";
    if (length && systemText) {
        stream << L": " << systemText;
    }
    if (systemText) {
        LocalFree(systemText);
    }
    return stream.str();
}

void requireSuccess(DWORD status, const wchar_t* operation) {
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error(
            std::string(errorMessage(operation, status).begin(),
                        errorMessage(operation, status).end()));
    }
}

std::string narrow(const std::wstring& value) {
    if (value.empty()) return {};
    const int count = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string out(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), out.data(), count, nullptr, nullptr);
    return out;
}

class Engine final {
public:
    Engine() {
        FWPM_SESSION0 session{};
        const DWORD status = FwpmEngineOpen0(
            nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &handle_);
        requireSuccess(status, L"FwpmEngineOpen0");
    }
    ~Engine() {
        if (handle_) FwpmEngineClose0(handle_);
    }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_ = nullptr;
};

class Transaction final {
public:
    explicit Transaction(HANDLE engine) : engine_(engine) {
        requireSuccess(FwpmTransactionBegin0(engine_, 0), L"FwpmTransactionBegin0");
        active_ = true;
    }
    ~Transaction() {
        if (active_) {
            FwpmTransactionAbort0(engine_);
        }
    }
    void commit() {
        requireSuccess(FwpmTransactionCommit0(engine_), L"FwpmTransactionCommit0");
        active_ = false;
    }

private:
    HANDLE engine_;
    bool active_ = false;
};

struct Condition {
    FWPM_FILTER_CONDITION0 value{};
    FWP_BYTE_BLOB* blobToFree = nullptr;
};

Condition uint8Condition(const GUID& key, UINT8 value) {
    Condition out{};
    out.value.fieldKey = key;
    out.value.matchType = FWP_MATCH_EQUAL;
    out.value.conditionValue.type = FWP_UINT8;
    out.value.conditionValue.uint8 = value;
    return out;
}

Condition uint16Condition(const GUID& key, UINT16 value) {
    Condition out{};
    out.value.fieldKey = key;
    out.value.matchType = FWP_MATCH_EQUAL;
    out.value.conditionValue.type = FWP_UINT16;
    out.value.conditionValue.uint16 = value;
    return out;
}

Condition uint64Condition(const GUID& key, UINT64* value) {
    Condition out{};
    out.value.fieldKey = key;
    out.value.matchType = FWP_MATCH_EQUAL;
    out.value.conditionValue.type = FWP_UINT64;
    out.value.conditionValue.uint64 = value;
    return out;
}

Condition loopbackCondition() {
    Condition out{};
    out.value.fieldKey = FWPM_CONDITION_FLAGS;
    out.value.matchType = FWP_MATCH_FLAGS_ALL_SET;
    out.value.conditionValue.type = FWP_UINT32;
    out.value.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    return out;
}

Condition appIdCondition(FWP_BYTE_BLOB* appId) {
    Condition out{};
    out.value.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    out.value.matchType = FWP_MATCH_EQUAL;
    out.value.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    out.value.conditionValue.byteBlob = appId;
    out.blobToFree = appId;
    return out;
}

void addFilter(
    HANDLE engine,
    const GUID& layer,
    const wchar_t* displayName,
    FWP_ACTION_TYPE action,
    const std::vector<Condition>& conditions,
    UINT64 weight) {

    std::vector<FWPM_FILTER_CONDITION0> rawConditions;
    rawConditions.reserve(conditions.size());
    for (const auto& condition : conditions) {
        rawConditions.push_back(condition.value);
    }

    FWPM_FILTER0 filter{};
    CoCreateGuid(&filter.filterKey);
    filter.displayData.name = const_cast<wchar_t*>(displayName);
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = const_cast<GUID*>(&kProviderKey);
    filter.layerKey = layer;
    filter.subLayerKey = kSubLayerKey;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.action.type = action;
    filter.numFilterConditions = static_cast<UINT32>(rawConditions.size());
    filter.filterCondition = rawConditions.empty() ? nullptr : rawConditions.data();

    const DWORD status = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    for (const auto& condition : conditions) {
        if (condition.blobToFree) {
            FwpmFreeMemory0(reinterpret_cast<void**>(
                const_cast<FWP_BYTE_BLOB**>(&condition.blobToFree)));
        }
    }
    requireSuccess(status, L"FwpmFilterAdd0");
}

void addAppPermit(HANDLE engine, const std::wstring& path,
                  const GUID& layer, const wchar_t* label) {
    FWP_BYTE_BLOB* appId = nullptr;
    requireSuccess(FwpmGetAppIdFromFileName0(path.c_str(), &appId),
                   L"FwpmGetAppIdFromFileName0");
    std::vector<Condition> conditions;
    conditions.push_back(appIdCondition(appId));
    addFilter(engine, layer, label, FWP_ACTION_PERMIT, conditions, 1000);
}

void addLoopbackPermit(HANDLE engine, const GUID& layer) {
    addFilter(engine, layer, L"TorProxy WFP permit loopback",
              FWP_ACTION_PERMIT, {loopbackCondition()}, 900);
}

void addInterfacePermit(HANDLE engine, const GUID& layer, UINT64* luid) {
    addFilter(engine, layer, L"TorProxy WFP permit TorProxy tunnel interface",
              FWP_ACTION_PERMIT,
              {uint64Condition(FWPM_CONDITION_IP_LOCAL_INTERFACE, luid)}, 950);
}

void addDhcpPermit(HANDLE engine, const GUID& layer, UINT16 localPort, UINT16 remotePort,
                   const wchar_t* label) {
    std::vector<Condition> conditions;
    conditions.push_back(uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP));
    conditions.push_back(uint16Condition(FWPM_CONDITION_IP_LOCAL_PORT, localPort));
    conditions.push_back(uint16Condition(FWPM_CONDITION_IP_REMOTE_PORT, remotePort));
    addFilter(engine, layer, label, FWP_ACTION_PERMIT, conditions, 850);
}

void addIcmpv6Permit(HANDLE engine, UINT16 type) {
    std::vector<Condition> conditions;
    conditions.push_back(uint8Condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_ICMPV6));
    conditions.push_back(uint16Condition(FWPM_CONDITION_ICMP_TYPE, type));
    addFilter(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
              L"TorProxy WFP permit IPv6 neighbor discovery",
              FWP_ACTION_PERMIT, conditions, 850);
}

void addProviderAndSublayer(HANDLE engine) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = kProviderKey;
    provider.displayData.name = const_cast<wchar_t*>(L"TorProxy Kill Switch");
    provider.displayData.description =
        const_cast<wchar_t*>(L"Persistent WFP policy owned by TorProxy");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    DWORD status = FwpmProviderAdd0(engine, &provider, nullptr);
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
        requireSuccess(status, L"FwpmProviderAdd0");
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kSubLayerKey;
    sublayer.displayData.name = const_cast<wchar_t*>(L"TorProxy Kill Switch");
    sublayer.displayData.description =
        const_cast<wchar_t*>(L"TorProxy application exceptions and default deny");
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = const_cast<GUID*>(&kProviderKey);
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
        requireSuccess(status, L"FwpmSubLayerAdd0");
    }
}

UINT32 enumerateOwnedFilters(HANDLE engine, std::vector<GUID>* keys) {
    FWPM_FILTER_ENUM_TEMPLATE0 filterTemplate{};
    filterTemplate.providerKey = const_cast<GUID*>(&kProviderKey);

    HANDLE enumHandle = nullptr;
    requireSuccess(FwpmFilterCreateEnumHandle0(engine, &filterTemplate, &enumHandle),
                   L"FwpmFilterCreateEnumHandle0");

    UINT32 total = 0;
    try {
        for (;;) {
            FWPM_FILTER0** entries = nullptr;
            UINT32 count = 0;
            requireSuccess(FwpmFilterEnum0(engine, enumHandle, 128, &entries, &count),
                           L"FwpmFilterEnum0");
            if (count == 0) {
                if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                break;
            }
            total += count;
            if (keys) {
                for (UINT32 index = 0; index < count; ++index) {
                    keys->push_back(entries[index]->filterKey);
                }
            }
            FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
        }
    } catch (...) {
        FwpmFilterDestroyEnumHandle0(engine, enumHandle);
        throw;
    }
    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    return total;
}

void removeOwnedFilters(HANDLE engine) {
    std::vector<GUID> keys;
    enumerateOwnedFilters(engine, &keys);
    for (const GUID& key : keys) {
        requireSuccess(FwpmFilterDeleteByKey0(engine, &key), L"FwpmFilterDeleteByKey0");
    }
}

void activate(const std::vector<std::wstring>& programs) {
    if (programs.empty()) {
        throw std::runtime_error("At least one Tor executable path is required.");
    }
    for (const auto& path : programs) {
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            throw std::runtime_error("An allowlisted Tor application does not exist.");
        }
    }

    Engine engine;
    Transaction transaction(engine.get());
    removeOwnedFilters(engine.get());
    addProviderAndSublayer(engine.get());

    for (const auto& path : programs) {
        addAppPermit(engine.get(), path, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                     L"TorProxy WFP permit Tor application IPv4");
        addAppPermit(engine.get(), path, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                     L"TorProxy WFP permit Tor application IPv6");
    }

    addLoopbackPermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V4);
    addLoopbackPermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V6);

    NET_LUID tunnelLuid{};
    if (ConvertInterfaceNameToLuidW(L"TorProxy", &tunnelLuid) == NO_ERROR) {
        addInterfacePermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V4, &tunnelLuid.Value);
        addInterfacePermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V6, &tunnelLuid.Value);
    }

    addDhcpPermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V4, 68, 67,
                  L"TorProxy WFP permit DHCPv4");
    addDhcpPermit(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V6, 546, 547,
                  L"TorProxy WFP permit DHCPv6");

    addIcmpv6Permit(engine.get(), 133); // Router solicitation
    addIcmpv6Permit(engine.get(), 135); // Neighbor solicitation
    addIcmpv6Permit(engine.get(), 136); // Neighbor advertisement

    // Permit filters have higher weights within this sublayer. Do not set
    // CLEAR_ACTION_RIGHT: lower-priority enterprise/security filters may still
    // veto a permit. The terminal TorProxy block prevents ordinary Allow rules
    // in lower sublayers from reopening non-Tor outbound traffic.
    addFilter(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V4,
              L"TorProxy WFP default outbound deny IPv4",
              FWP_ACTION_BLOCK, {}, 1);
    addFilter(engine.get(), FWPM_LAYER_ALE_AUTH_CONNECT_V6,
              L"TorProxy WFP default outbound deny IPv6",
              FWP_ACTION_BLOCK, {}, 1);

    transaction.commit();

    const UINT32 installed = enumerateOwnedFilters(engine.get(), nullptr);
    if (installed < 10) {
        throw std::runtime_error("WFP transaction committed, but the installed filter set is incomplete.");
    }
    std::wcout << L"ACTIVE filters=" << installed << L"\n";
}

void recover() {
    Engine engine;
    Transaction transaction(engine.get());
    removeOwnedFilters(engine.get());
    transaction.commit();
    std::wcout << L"INACTIVE filters=0\n";
}

void status() {
    Engine engine;
    const UINT32 count = enumerateOwnedFilters(engine.get(), nullptr);
    std::wcout << (count >= 10 ? L"ACTIVE" : L"INACTIVE")
               << L" filters=" << count << L"\n";
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc < 2) {
            std::wcerr << L"Usage: TorProxyWfpHelper.exe activate <tor.exe> [bridge.exe...] | recover | status\n";
            return 2;
        }
        const std::wstring action = argv[1];
        if (action == L"activate") {
            std::vector<std::wstring> programs;
            for (int i = 2; i < argc; ++i) programs.emplace_back(argv[i]);
            activate(programs);
        } else if (action == L"recover" || action == L"emergency") {
            recover();
        } else if (action == L"status") {
            status();
        } else {
            std::wcerr << L"Unsupported WFP action.\n";
            return 2;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown WFP helper failure.\n";
        return 1;
    }
}
