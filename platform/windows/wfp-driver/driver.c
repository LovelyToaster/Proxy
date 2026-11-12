#include <ntifs.h>
#include <wdmsec.h>
#define NDIS630 1
#pragma warning(push)
#pragma warning(disable: 4201) // WDK headers use anonymous structs and unions.
#include <ndis.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <initguid.h>
#include <fwpmk.h>
#include <fwpsk.h>
#pragma warning(pop)

#include "protocol.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10
#endif

#define PROXY_TAG 'pfwP'
#define PROXY_LEASE_TICKS (3ull * 1000ull * 10000ull)

static const GUID ProviderKey = {0x3945f149,0xa5d2,0x4dc1,{0x9c,0xc6,0x3c,0x6b,0x3d,0x19,0xe2,0x77}};
static const GUID SublayerKey = {0xc8247cf0,0x04b4,0x45f3,{0x94,0x22,0xd2,0x07,0x17,0x2d,0x92,0xf4}};
static const GUID Callout4Key = {0x88af4c2d,0xc782,0x48ef,{0x8e,0x91,0xec,0xb4,0x01,0x0f,0x35,0xe1}};
static const GUID Callout6Key = {0x24a239d0,0x2d81,0x40e2,{0xa4,0xb7,0x14,0x45,0xa9,0xdc,0x1c,0xe7}};
static const GUID UDPFlowKey[2] = {
    {0x5ab4716e,0x59c4,0x4ced,{0xa3,0xe3,0x83,0xee,0xd1,0x15,0xda,0x40}},
    {0xd4d15553,0xc3d8,0x421f,{0xad,0x04,0xd0,0x88,0x47,0xaa,0xe7,0xb9}}
};
static const GUID UDPDataKey[2] = {
    {0xbce51abc,0xf679,0x4aa2,{0x83,0xd7,0xf9,0x5d,0x62,0xbd,0x54,0x90}},
    {0x6e2823ab,0x55c8,0x4a7f,{0x9b,0xf2,0xbc,0x55,0xa4,0x65,0x35,0x11}}
};
static const GUID DeviceClass = {0xd4bfca51,0x8fc6,0x4c82,{0x8f,0xde,0x26,0xd6,0x88,0x13,0xbe,0x32}};

static UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ProxyWfp");
static UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProxyWfp");

typedef struct _LEASE {
    UINT64 Deadline;
    UINT64 Filters[2][6];
    UINT32 OwnerPid;
    PROXY_REGISTRATION Config;
} LEASE;

static KSPIN_LOCK LeaseLock;
static LEASE CurrentLease;
static KEVENT ManagementGate;
static PFILE_OBJECT OwnerFile;
static PEPROCESS OwnerProcess;
static HANDLE Engine;
static HANDLE RedirectHandle;
static UINT32 Callout4;
static UINT32 Callout6;
static UINT32 UDPFlowCallout[2];
static UINT32 UDPDataCallout[2];
static HANDLE UDPInjection;
static NDIS_HANDLE UDPPool;
static UINT64 UDPDrops;
static VOID ClearUDP(VOID);

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverUnload;

static BOOLEAN AllZero(const UCHAR *bytes, SIZE_T count)
{
    SIZE_T i;
    for (i = 0; i < count; ++i)
        if (bytes[i] != 0)
            return FALSE;
    return TRUE;
}

static BOOLEAN EqualBytes(const VOID *first, const VOID *second, SIZE_T length)
{
    return RtlCompareMemory(first, second, length) == length;
}

static BOOLEAN ValidRegistration(const PROXY_REGISTRATION *config, ULONG size)
{
    if (size < sizeof(*config) || config->Size != size || config->Version != PROXY_VERSION ||
        (config->Flags & ~(PROXY_UDP | PROXY_DNS)) != 0 || config->Families == 0 ||
        (config->Families & ~(PROXY_IPV4 | PROXY_IPV6)) != 0 ||
        config->ListenPort < 1024 || config->ListenPort > 65535 ||
        (config->TargetPort != 0 && config->TargetPort < 1024) || config->TargetPort > 65535 ||
        (config->TargetPort == 0 && config->Flags != PROXY_DNS) ||
        config->TargetPort == config->ListenPort ||
        config->AppIdLength < 2 || config->AppIdLength > PROXY_MAX_APP_ID ||
        (config->AppIdLength & 1) != 0 || config->AppIdLength != size - sizeof(*config))
        return FALSE;

    if (config->Families & PROXY_IPV4) {
        if (config->Target4[0] == 0 || config->Target4[0] >= 224 ||
            (config->Flags != 0 && config->Target4[0] != 127))
            return FALSE;
    } else if (!AllZero(config->Target4, sizeof(config->Target4))) {
        return FALSE;
    }

    if (config->Families & PROXY_IPV6) {
        const UCHAR *addr = config->Target6;
        if (AllZero(addr, 16) || addr[0] == 0xff || (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) ||
            (AllZero(addr, 10) && addr[10] == 0xff && addr[11] == 0xff) ||
            (config->Flags != 0 && (!AllZero(addr, 15) || addr[15] != 1)))
            return FALSE;
    } else if (!AllZero(config->Target6, sizeof(config->Target6))) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS AddCallout(HANDLE engine, const GUID *key, const GUID *layer)
{
    FWPM_CALLOUT0 callout = {0};
    callout.calloutKey = *key;
    callout.providerKey = (GUID *)&ProviderKey;
    callout.applicableLayer = *layer;
    callout.displayData.name = L"ProxyWfp scoped callout";
    return FwpmCalloutAdd0(engine, &callout, NULL, NULL);
}

static NTSTATUS AddFilter(HANDLE engine, const PROXY_REGISTRATION *config, BOOLEAN ipv6,
                          const GUID *key, const GUID *layer, UINT8 protocol, UINT16 port,
                          BOOLEAN matchApplication, UINT64 *id)
{
    FWPM_FILTER0 filter = {0};
    FWPM_FILTER_CONDITION0 conditions[5] = {0};
    FWP_BYTE_BLOB appId;
    FWP_BYTE_ARRAY16 address6;
    ULONG address4;
    appId.size = config->AppIdLength;
    appId.data = (UINT8 *)(config + 1);
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = &appId;
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = protocol;
    conditions[2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    if (ipv6) {
        RtlCopyMemory(address6.byteArray16, config->Target6, sizeof(config->Target6));
        conditions[2].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        conditions[2].conditionValue.byteArray16 = &address6;
    } else {
        RtlCopyMemory(&address4, config->Target4, sizeof(address4));
        conditions[2].conditionValue.type = FWP_UINT32;
        conditions[2].conditionValue.uint32 = RtlUlongByteSwap(address4);
    }
    conditions[3].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[3].conditionValue.type = FWP_UINT16;
    conditions[3].conditionValue.uint16 = port;
    conditions[4].fieldKey = FWPM_CONDITION_DIRECTION;
    conditions[4].conditionValue.type = FWP_UINT32;
    conditions[4].conditionValue.uint32 = FWP_DIRECTION_OUTBOUND;
    for (ULONG i = 0; i < RTL_NUMBER_OF(conditions); ++i)
        conditions[i].matchType = FWP_MATCH_EQUAL;

    filter.displayData.name = L"ProxyWfp scoped capture";
    filter.providerKey = (GUID *)&ProviderKey;
    filter.layerKey = *layer;
    filter.subLayerKey = SublayerKey;
    filter.action.type = key == &UDPFlowKey[ipv6] ? FWP_ACTION_CALLOUT_INSPECTION : FWP_ACTION_CALLOUT_UNKNOWN;
    if (filter.action.type != FWP_ACTION_CALLOUT_INSPECTION)
        filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    filter.action.calloutKey = *key;
    filter.numFilterConditions = (UINT32)RTL_NUMBER_OF(conditions) - 1;
    filter.filterCondition = conditions + (matchApplication ? 0 : 1);
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd0(engine, &filter, NULL, id);
}

static NTSTATUS AddFamily(const PROXY_REGISTRATION *config, BOOLEAN ipv6, UINT64 ids[6])
{
    const GUID *tcpKey = ipv6 ? &Callout6Key : &Callout4Key;
    const GUID *tcpLayer = ipv6 ? &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6 : &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    const GUID *flowLayer = ipv6 ? &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6 : &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    const GUID *dataLayer = ipv6 ? &FWPM_LAYER_DATAGRAM_DATA_V6 : &FWPM_LAYER_DATAGRAM_DATA_V4;
    NTSTATUS status = AddCallout(Engine, tcpKey, tcpLayer);
    if (!NT_SUCCESS(status))
        return status;
    if (config->Flags != 0) {
        status = AddCallout(Engine, &UDPFlowKey[ipv6], flowLayer);
        if (!NT_SUCCESS(status))
            return status;
        status = AddCallout(Engine, &UDPDataKey[ipv6], dataLayer);
        if (!NT_SUCCESS(status))
            return status;
    }
    for (UINT32 i = 0; i < 2; ++i) {
        UINT16 port = i == 0 ? (UINT16)config->TargetPort : 53;
        UINT32 flag = i == 0 ? PROXY_UDP : PROXY_DNS;
        if (port == 0 || (i == 1 && !(config->Flags & PROXY_DNS)))
            continue;
        status = AddFilter(Engine, config, ipv6, tcpKey, tcpLayer, IPPROTO_TCP, port, TRUE, &ids[i]);
        if (!NT_SUCCESS(status))
            return status;
        if (!(config->Flags & flag))
            continue;
        status = AddFilter(Engine, config, ipv6, &UDPFlowKey[ipv6], flowLayer, IPPROTO_UDP, port, TRUE, &ids[i + 2]);
        if (!NT_SUCCESS(status))
            return status;
        status = AddFilter(Engine, config, ipv6, &UDPDataKey[ipv6], dataLayer, IPPROTO_UDP, port, FALSE, &ids[i + 4]);
        if (!NT_SUCCESS(status))
            return status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS Disarm(VOID)
{
    KIRQL irql;
    NTSTATUS status;
    KeAcquireSpinLock(&LeaseLock, &irql);
    RtlZeroMemory(&CurrentLease, sizeof(CurrentLease));
    KeReleaseSpinLock(&LeaseLock, irql);
    ClearUDP();
    if (Engine == NULL)
        return STATUS_SUCCESS;
    status = FwpmEngineClose0(Engine);
    if (NT_SUCCESS(status))
        Engine = NULL;
    return status;
}

static NTSTATUS Arm(const PROXY_REGISTRATION *config)
{
    FWPM_SESSION0 session = {0};
    FWPM_PROVIDER0 provider = {0};
    FWPM_SUBLAYER0 sublayer = {0};
    LEASE next = {0};
    KIRQL irql;
    NTSTATUS status;

    if (Engine != NULL)
        return STATUS_DEVICE_BUSY;

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"ProxyWfp temporary capture";
    session.txnWaitTimeoutInMSec = 2000;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &Engine);
    if (!NT_SUCCESS(status)) {
        Engine = NULL;
        return status;
    }
    status = FwpmTransactionBegin0(Engine, 0);
    if (!NT_SUCCESS(status))
        goto Fail;

    provider.providerKey = ProviderKey;
    provider.displayData.name = L"ProxyWfp";
    status = FwpmProviderAdd0(Engine, &provider, NULL);
    if (!NT_SUCCESS(status))
        goto Abort;
    sublayer.subLayerKey = SublayerKey;
    sublayer.displayData.name = L"ProxyWfp scoped redirection";
    sublayer.providerKey = (GUID *)&ProviderKey;
    sublayer.weight = 0x100;
    status = FwpmSubLayerAdd0(Engine, &sublayer, NULL);
    if (!NT_SUCCESS(status))
        goto Abort;
    if (config->Families & PROXY_IPV4) {
        status = AddFamily(config, FALSE, next.Filters[0]);
        if (!NT_SUCCESS(status))
            goto Abort;
    }
    if (config->Families & PROXY_IPV6) {
        status = AddFamily(config, TRUE, next.Filters[1]);
        if (!NT_SUCCESS(status))
            goto Abort;
    }
    status = FwpmTransactionCommit0(Engine);
    if (!NT_SUCCESS(status))
        goto Abort;

    next.Config = *config;
    next.OwnerPid = HandleToULong(PsGetProcessId(OwnerProcess));
    next.Deadline = KeQueryInterruptTime() + PROXY_LEASE_TICKS;
    KeAcquireSpinLock(&LeaseLock, &irql);
    CurrentLease = next;
    UDPDrops = 0;
    KeReleaseSpinLock(&LeaseLock, irql);
    return STATUS_SUCCESS;

Abort:
    (VOID)FwpmTransactionAbort0(Engine);
Fail:
    (VOID)Disarm();
    return status;
}

static NTSTATUS Renew(VOID)
{
    NTSTATUS status = STATUS_TIMEOUT;
    KIRQL irql;
    UINT64 now;
    KeAcquireSpinLock(&LeaseLock, &irql);
    now = KeQueryInterruptTime();
    if (CurrentLease.Deadline > now) {
        CurrentLease.Deadline = now + PROXY_LEASE_TICKS;
        status = STATUS_SUCCESS;
    } else {
        CurrentLease.Deadline = 0;
    }
    KeReleaseSpinLock(&LeaseLock, irql);
    /* STATUS_TIMEOUT is informational; return a failure for an expired lease. */
    return status == STATUS_SUCCESS ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}

static BOOLEAN DestinationMatches(
    FWPS_CONNECT_REQUEST0 *request, const LEASE *lease, BOOLEAN ipv6, UINT16 targetPort,
    PROXY_REDIRECT_CONTEXT *context)
{
    if (request->localRedirectHandle != NULL || request->localRedirectContext != NULL)
        return FALSE;
    if (ipv6) {
        const SOCKADDR_IN6 *local = (const SOCKADDR_IN6 *)&request->localAddressAndPort;
        const SOCKADDR_IN6 *remote = (const SOCKADDR_IN6 *)&request->remoteAddressAndPort;
        const UCHAR *source = (const UCHAR *)&local->sin6_addr;
        if (local->sin6_family != AF_INET6 || remote->sin6_family != AF_INET6 || remote->sin6_scope_id != 0 ||
            !AllZero(source, 15) || source[15] > 1 ||
            RtlUshortByteSwap(remote->sin6_port) != targetPort ||
            !EqualBytes(&remote->sin6_addr, lease->Config.Target6, sizeof(lease->Config.Target6)))
            return FALSE;
        context->Family = 6;
        RtlCopyMemory(context->Address, &remote->sin6_addr, sizeof(context->Address));
    } else {
        const SOCKADDR_IN *local = (const SOCKADDR_IN *)&request->localAddressAndPort;
        const SOCKADDR_IN *remote = (const SOCKADDR_IN *)&request->remoteAddressAndPort;
        if (local->sin_family != AF_INET || remote->sin_family != AF_INET ||
            (local->sin_addr.s_addr != 0 && ((const UCHAR *)&local->sin_addr)[0] != 127) ||
            RtlUshortByteSwap(remote->sin_port) != targetPort ||
            !EqualBytes(&remote->sin_addr, lease->Config.Target4, sizeof(lease->Config.Target4)))
            return FALSE;
        context->Family = 4;
        RtlCopyMemory(context->Address, &remote->sin_addr, sizeof(lease->Config.Target4));
    }
    context->Magic = PROXY_CONTEXT_MAGIC;
    context->Size = (UINT32)sizeof(*context);
    context->Port = targetPort;
    return TRUE;
}

static VOID SetLoopback(FWPS_CONNECT_REQUEST0 *request, BOOLEAN ipv6, UINT16 port)
{
    RtlZeroMemory(&request->remoteAddressAndPort, sizeof(request->remoteAddressAndPort));
    if (ipv6) {
        SOCKADDR_IN6 *address = (SOCKADDR_IN6 *)&request->remoteAddressAndPort;
        address->sin6_family = AF_INET6;
        address->sin6_port = RtlUshortByteSwap(port);
        ((UCHAR *)&address->sin6_addr)[15] = 1;
    } else {
        SOCKADDR_IN *address = (SOCKADDR_IN *)&request->remoteAddressAndPort;
        address->sin_family = AF_INET;
        address->sin_port = RtlUshortByteSwap(port);
        ((UCHAR *)&address->sin_addr)[0] = 127;
        ((UCHAR *)&address->sin_addr)[3] = 1;
    }
}

static VOID NTAPI Classify(
    const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    VOID *layerData,
    const VOID *classifyContext,
    const FWPS_FILTER1 *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0 *output)
{
    BOOLEAN ipv6;
    LEASE lease;
    KIRQL irql;
    UINT64 handle;
    FWPS_CONNECT_REQUEST0 *request = NULL;
    PROXY_REDIRECT_CONTEXT original = {0};
    PROXY_REDIRECT_CONTEXT *context;
    FWPS_CLASSIFY_OUT0 prior;
    UINT32 rule;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);
    if ((output->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;
    output->actionType = FWP_ACTION_CONTINUE;
    if (classifyContext == NULL || !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID))
        return;
    if (values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 &&
        values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6)
        return;
    ipv6 = values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6;

    KeAcquireSpinLock(&LeaseLock, &irql);
    lease = CurrentLease;
    KeReleaseSpinLock(&LeaseLock, irql);
    rule = filter->filterId == lease.Filters[ipv6][1] ? 1u : 0u;
    if (lease.Deadline <= KeQueryInterruptTime() || metadata->processId == lease.OwnerPid ||
        filter->filterId != lease.Filters[ipv6][rule])
        return;
    if (FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE) &&
        metadata->redirectRecords != NULL &&
        FwpsQueryConnectionRedirectState0(metadata->redirectRecords, RedirectHandle, NULL) != FWPS_CONNECTION_NOT_REDIRECTED)
        return;
    if (!NT_SUCCESS(FwpsAcquireClassifyHandle0((VOID *)classifyContext, 0, &handle)))
        return;

    prior = *output;
    if (NT_SUCCESS(FwpsAcquireWritableLayerDataPointer0(handle, filter->filterId, 0, (VOID **)&request, output))) {
        *output = prior;
        if (request != NULL && DestinationMatches(request, &lease, ipv6,
                rule == 0 ? (UINT16)lease.Config.TargetPort : 53, &original)) {
            context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(original), PROXY_TAG);
            if (context != NULL) {
                BOOLEAN stillArmed;
                KeAcquireSpinLock(&LeaseLock, &irql);
                stillArmed = CurrentLease.Deadline > KeQueryInterruptTime() &&
                    filter->filterId == CurrentLease.Filters[ipv6][rule];
                KeReleaseSpinLock(&LeaseLock, irql);
                if (stillArmed) {
                    *context = original;
                    SetLoopback(request, ipv6, (UINT16)lease.Config.ListenPort);
                    request->localRedirectTargetPID = lease.OwnerPid;
                    request->localRedirectHandle = RedirectHandle;
                    request->localRedirectContext = context;
                    request->localRedirectContextSize = sizeof(*context);
                    output->actionType = FWP_ACTION_PERMIT;
                    /* WFP owns the context once the modified data is applied. */
                } else {
                    ExFreePoolWithTag(context, PROXY_TAG);
                }
            }
        }
        if (request != NULL)
            FwpsApplyModifiedLayerData0(handle, request, 0);
    } else {
        *output = prior;
    }
    FwpsReleaseClassifyHandle0(handle);
}

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter)
{
    KIRQL irql;
    UNREFERENCED_PARAMETER(key);
    if (type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER && filter != NULL) {
        KeAcquireSpinLock(&LeaseLock, &irql);
        for (UINT32 family = 0; family < 2; ++family)
            for (UINT32 i = 0; i < RTL_NUMBER_OF(CurrentLease.Filters[0]); ++i)
                if (filter->filterId == CurrentLease.Filters[family][i])
                    CurrentLease.Deadline = 0;
        KeReleaseSpinLock(&LeaseLock, irql);
    }
    return STATUS_SUCCESS;
}

#define UDP_FLOW_COUNT 256u
#define UDP_QUEUE_BYTES (1024u * 1024u)
#define UDP_MAX_PAYLOAD 65507u
#define UDP_MAX_INFLIGHT 64
#define UDP_HEADER_SIZE 8u

typedef struct _UDP_FLOW {
    UINT64 Cookie;
    UINT64 Handle;
    BOOLEAN IPv6;
    BOOLEAN HasEndpoint;
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT32 Interface;
    UINT32 SubInterface;
    COMPARTMENT_ID Compartment;
    UCHAR Local[16];
    UCHAR Remote[16];
} UDP_FLOW;

typedef struct _UDP_PACKET {
    LIST_ENTRY Link;
    ULONG Size;
    PROXY_UDP_HEADER Header;
    UCHAR Data[ANYSIZE_ARRAY];
} UDP_PACKET;

typedef struct _UDP_INJECTION {
    PMDL Mdl;
    UCHAR Data[ANYSIZE_ARRAY];
} UDP_INJECTION;

static UDP_FLOW UDPFlows[UDP_FLOW_COUNT];
static LIST_ENTRY UDPQueue;
static ULONG UDPQueueBytes;
static UINT64 LastCookie;
static ULONG UDPActiveFlows;
static KEVENT UDPFlowsDrained;
static volatile LONG UDPInFlight;

static UINT16 DatagramLayer(BOOLEAN ipv6)
{
    return (UINT16)(ipv6 ? FWPS_LAYER_DATAGRAM_DATA_V6 : FWPS_LAYER_DATAGRAM_DATA_V4);
}

static UDP_FLOW *FindUDPFlow(UINT64 cookie)
{
    UDP_FLOW *flow = &UDPFlows[cookie % UDP_FLOW_COUNT];
    return cookie != 0 && flow->Cookie == cookie ? flow : NULL;
}

static VOID NTAPI DeleteUDPFlow(UINT16 layerId, UINT32 calloutId, UINT64 cookie)
{
    KIRQL irql;
    UDP_FLOW *flow;
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    KeAcquireSpinLock(&LeaseLock, &irql);
    flow = FindUDPFlow(cookie);
    if (flow != NULL) {
        RtlZeroMemory(flow, sizeof(*flow));
        if (--UDPActiveFlows == 0)
            KeSetEvent(&UDPFlowsDrained, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&LeaseLock, irql);
}

static VOID ClearUDP(VOID)
{
    KIRQL irql;
    LIST_ENTRY retired;
    InitializeListHead(&retired);
    KeAcquireSpinLock(&LeaseLock, &irql);
    while (!IsListEmpty(&UDPQueue)) {
        LIST_ENTRY *entry = RemoveHeadList(&UDPQueue);
        InsertTailList(&retired, entry);
    }
    UDPQueueBytes = 0;
    KeReleaseSpinLock(&LeaseLock, irql);
    while (!IsListEmpty(&retired)) {
        LIST_ENTRY *entry = RemoveHeadList(&retired);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, UDP_PACKET, Link), PROXY_TAG);
    }

    for (UINT32 i = 0; i < UDP_FLOW_COUNT; ++i) {
        UDP_FLOW flow;
        KeAcquireSpinLock(&LeaseLock, &irql);
        flow = UDPFlows[i];
        KeReleaseSpinLock(&LeaseLock, irql);
        if (flow.Cookie != 0) {
            NTSTATUS status = FwpsFlowRemoveContext0(flow.Handle, DatagramLayer(flow.IPv6), UDPDataCallout[flow.IPv6]);
            if (status == STATUS_UNSUCCESSFUL)
                DeleteUDPFlow(DatagramLayer(flow.IPv6), UDPDataCallout[flow.IPv6], flow.Cookie);
        }
    }
    KeWaitForSingleObject(&UDPFlowsDrained, Executive, KernelMode, FALSE, NULL);
}

static VOID NTAPI ClassifyUDPFlow(
    const FWPS_INCOMING_VALUES0 *values, const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    VOID *layerData, const VOID *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *output)
{
    BOOLEAN ipv6 = values->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    KIRQL irql;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);
    if ((output->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;
    output->actionType = FWP_ACTION_CONTINUE;
    if (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_FLOW_HANDLE) ||
        values->incomingValue[ipv6 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION :
            FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32 != FWP_DIRECTION_OUTBOUND)
        return;

    KeAcquireSpinLock(&LeaseLock, &irql);
    if (CurrentLease.Deadline > KeQueryInterruptTime() &&
        (!FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID) ||
            metadata->processId != CurrentLease.OwnerPid) &&
        (filter->filterId == CurrentLease.Filters[ipv6][2] || filter->filterId == CurrentLease.Filters[ipv6][3])) {
        for (UINT32 i = 0; i < UDP_FLOW_COUNT; ++i) {
            UINT64 cookie = ++LastCookie;
            UDP_FLOW *flow = &UDPFlows[cookie % UDP_FLOW_COUNT];
            if (flow->Cookie != 0 || cookie == 0)
                continue;
            if (FwpsFlowAssociateContext0(metadata->flowHandle,
                    DatagramLayer(ipv6), UDPDataCallout[ipv6], cookie) == STATUS_SUCCESS) {
                flow->Cookie = cookie;
                flow->Handle = metadata->flowHandle;
                flow->IPv6 = ipv6;
                if (UDPActiveFlows++ == 0)
                    KeClearEvent(&UDPFlowsDrained);
            }
            break;
        }
    }
    KeReleaseSpinLock(&LeaseLock, irql);
}

static BOOLEAN ReadUDPAddresses(const FWPS_INCOMING_VALUES0 *values, BOOLEAN ipv6, UDP_FLOW *endpoint)
{
    const FWP_VALUE0 *local = &values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS :
        FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value;
    const FWP_VALUE0 *remote = &values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS :
        FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value;
    if (ipv6) {
        if (local->type != FWP_BYTE_ARRAY16_TYPE || remote->type != FWP_BYTE_ARRAY16_TYPE ||
            local->byteArray16 == NULL || remote->byteArray16 == NULL)
            return FALSE;
        RtlCopyMemory(endpoint->Local, local->byteArray16->byteArray16, 16);
        RtlCopyMemory(endpoint->Remote, remote->byteArray16->byteArray16, 16);
        return AllZero(endpoint->Local, 15) && endpoint->Local[15] == 1 &&
            AllZero(endpoint->Remote, 15) && endpoint->Remote[15] == 1;
    }
    if (local->type != FWP_UINT32 || remote->type != FWP_UINT32)
        return FALSE;
    {
        UINT32 local4 = RtlUlongByteSwap(local->uint32);
        UINT32 remote4 = RtlUlongByteSwap(remote->uint32);
        RtlCopyMemory(endpoint->Local, &local4, sizeof(local4));
        RtlCopyMemory(endpoint->Remote, &remote4, sizeof(remote4));
    }
    return endpoint->Local[0] == 127 && endpoint->Remote[0] == 127;
}

static UINT16 ReadBE16(const UCHAR *data)
{
    return (UINT16)(((UINT16)data[0] << 8) | data[1]);
}

static VOID NTAPI ClassifyUDPData(
    const FWPS_INCOMING_VALUES0 *values, const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    VOID *layerData, const VOID *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 cookie, FWPS_CLASSIFY_OUT0 *output)
{
    BOOLEAN ipv6 = values->layerId == FWPS_LAYER_DATAGRAM_DATA_V6;
    NET_BUFFER_LIST *list = layerData;
    NET_BUFFER *buffer;
    UDP_PACKET *packet;
    UDP_FLOW endpoint = {0};
    UDP_FLOW *flow;
    KIRQL irql;
    ULONG size, allocation;
    UCHAR *wire;
    const FWP_VALUE0 *interfaceIndex, *subInterfaceIndex;
    UNREFERENCED_PARAMETER(classifyContext);
    if ((output->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;
    output->actionType = FWP_ACTION_CONTINUE;
    if (cookie == 0 || list == NULL || NET_BUFFER_LIST_NEXT_NBL(list) != NULL ||
        values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION :
            FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32 != FWP_DIRECTION_OUTBOUND ||
        !FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_COMPARTMENT_ID) ||
        !ReadUDPAddresses(values, ipv6, &endpoint))
        return;

    endpoint.LocalPort = values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT :
        FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
    endpoint.RemotePort = values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT :
        FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
    interfaceIndex = &values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX :
        FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value;
    subInterfaceIndex = &values->incomingValue[ipv6 ? FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX :
        FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX].value;
    if (interfaceIndex->type == FWP_UINT32)
        endpoint.Interface = interfaceIndex->uint32;
    if (endpoint.Interface == 0 && FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_DESTINATION_INTERFACE_INDEX))
        endpoint.Interface = metadata->destinationInterfaceIndex;
    if (endpoint.Interface == 0 || endpoint.LocalPort == 0 || endpoint.RemotePort == 0)
        return;
    endpoint.SubInterface = subInterfaceIndex->type == FWP_UINT32 ? subInterfaceIndex->uint32 : 0;
    endpoint.Compartment = metadata->compartmentId;

    buffer = NET_BUFFER_LIST_FIRST_NB(list);
    if (buffer == NULL || NET_BUFFER_NEXT_NB(buffer) != NULL)
        return;
    size = NET_BUFFER_DATA_LENGTH(buffer);
    if (size < UDP_HEADER_SIZE || size > UDP_HEADER_SIZE + UDP_MAX_PAYLOAD)
        return;
    allocation = (ULONG)FIELD_OFFSET(UDP_PACKET, Data) + size;
    packet = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocation, PROXY_TAG);
    if (packet == NULL)
        return;
    wire = NdisGetDataBuffer(buffer, size, packet->Data, 1, 0);
    if (wire == NULL || ReadBE16(wire) != endpoint.LocalPort || ReadBE16(wire + 2) != endpoint.RemotePort ||
        ReadBE16(wire + 4) != size)
        goto Fail;
    packet->Size = size - UDP_HEADER_SIZE;
    RtlMoveMemory(packet->Data, wire + UDP_HEADER_SIZE, packet->Size);
    packet->Header.Cookie = cookie;
    packet->Header.Family = ipv6 ? 6u : 4u;
    packet->Header.Port = endpoint.RemotePort;
    RtlCopyMemory(packet->Header.Address, endpoint.Remote, sizeof(endpoint.Remote));

    KeAcquireSpinLock(&LeaseLock, &irql);
    flow = FindUDPFlow(cookie);
    if (flow != NULL && flow->IPv6 == ipv6 && CurrentLease.Deadline > KeQueryInterruptTime() &&
        (filter->filterId == CurrentLease.Filters[ipv6][4] || filter->filterId == CurrentLease.Filters[ipv6][5]) &&
        (!flow->HasEndpoint || (flow->LocalPort == endpoint.LocalPort && flow->RemotePort == endpoint.RemotePort &&
            flow->Compartment == endpoint.Compartment && EqualBytes(flow->Local, endpoint.Local, 16) &&
            EqualBytes(flow->Remote, endpoint.Remote, 16)))) {
        if (UDPQueueBytes + allocation <= UDP_QUEUE_BYTES) {
            endpoint.Cookie = flow->Cookie;
            endpoint.Handle = flow->Handle;
            endpoint.IPv6 = ipv6;
            endpoint.HasEndpoint = TRUE;
            *flow = endpoint;
            UDPQueueBytes += allocation;
            InsertTailList(&UDPQueue, &packet->Link);
            packet = NULL;
        } else {
            ++UDPDrops;
        }
        output->actionType = FWP_ACTION_BLOCK;
        output->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        output->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
    KeReleaseSpinLock(&LeaseLock, irql);

Fail:
    if (packet != NULL)
        ExFreePoolWithTag(packet, PROXY_TAG);
}

static NTSTATUS ReadUDP(VOID *buffer, ULONG capacity, ULONG_PTR *written)
{
    KIRQL irql;
    UDP_PACKET *packet = NULL;
    KeAcquireSpinLock(&LeaseLock, &irql);
    if (CurrentLease.Deadline > KeQueryInterruptTime() && !IsListEmpty(&UDPQueue)) {
        packet = CONTAINING_RECORD(UDPQueue.Flink, UDP_PACKET, Link);
        if (capacity < sizeof(packet->Header) + packet->Size) {
            KeReleaseSpinLock(&LeaseLock, irql);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RemoveEntryList(&packet->Link);
        UDPQueueBytes -= (ULONG)FIELD_OFFSET(UDP_PACKET, Data) + UDP_HEADER_SIZE + packet->Size;
    }
    KeReleaseSpinLock(&LeaseLock, irql);
    if (packet != NULL) {
        RtlCopyMemory(buffer, &packet->Header, sizeof(packet->Header));
        RtlCopyMemory((UCHAR *)buffer + sizeof(packet->Header), packet->Data, packet->Size);
        *written = sizeof(packet->Header) + packet->Size;
        ExFreePoolWithTag(packet, PROXY_TAG);
    }
    return STATUS_SUCCESS;
}

static VOID WriteBE16(UCHAR *data, UINT16 value)
{
    data[0] = (UCHAR)(value >> 8);
    data[1] = (UCHAR)value;
}

static UINT32 ChecksumSum(const UCHAR *data, ULONG size)
{
    UINT32 sum = 0;
    while (size >= 2) {
        sum += ReadBE16(data);
        data += 2;
        size -= 2;
    }
    return size == 0 ? sum : sum + ((UINT32)*data << 8);
}

static UINT16 FoldChecksum(UINT32 sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (UINT16)~sum;
}

static VOID BuildUDPReply(const UDP_FLOW *flow, UCHAR *ip, const UCHAR *payload, ULONG size)
{
    ULONG ipSize = flow->IPv6 ? 40u : 20u;
    UINT16 udpSize = (UINT16)(UDP_HEADER_SIZE + size);
    UCHAR *udp = ip + ipSize;
    UINT16 checksum;
    UINT32 addrSize = flow->IPv6 ? 16u : 4u;
    if (flow->IPv6) {
        ip[0] = 0x60;
        WriteBE16(ip + 4, udpSize);
        ip[6] = IPPROTO_UDP;
        ip[7] = 64;
        RtlCopyMemory(ip + 8, flow->Remote, addrSize);
        RtlCopyMemory(ip + 24, flow->Local, addrSize);
    } else {
        ip[0] = 0x45;
        WriteBE16(ip + 2, (UINT16)(ipSize + udpSize));
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        RtlCopyMemory(ip + 12, flow->Remote, addrSize);
        RtlCopyMemory(ip + 16, flow->Local, addrSize);
        WriteBE16(ip + 10, FoldChecksum(ChecksumSum(ip, ipSize)));
    }
    WriteBE16(udp, flow->RemotePort);
    WriteBE16(udp + 2, flow->LocalPort);
    WriteBE16(udp + 4, udpSize);
    RtlCopyMemory(udp + UDP_HEADER_SIZE, payload, size);
    checksum = FoldChecksum(ChecksumSum(flow->Remote, addrSize) + ChecksumSum(flow->Local, addrSize) +
        IPPROTO_UDP + udpSize + ChecksumSum(udp, udpSize));
    WriteBE16(udp + 6, checksum == 0 ? 0xffffu : checksum);
}

static VOID NTAPI FreeUDPInjection(VOID *context, NET_BUFFER_LIST *list, BOOLEAN dispatchLevel)
{
    UDP_INJECTION *packet = context;
    UNREFERENCED_PARAMETER(dispatchLevel);
    if (list != NULL)
        FwpsFreeNetBufferList0(list);
    if (packet != NULL) {
        if (packet->Mdl != NULL)
            IoFreeMdl(packet->Mdl);
        ExFreePoolWithTag(packet, PROXY_TAG);
    }
    InterlockedDecrement(&UDPInFlight);
}

static NTSTATUS ReplyUDP(const UCHAR *input, ULONG length)
{
    UDP_FLOW *active;
    UDP_FLOW flow;
    UINT64 cookie;
    KIRQL irql;
    ULONG size, total;
    UDP_INJECTION *packet;
    NET_BUFFER_LIST *list = NULL;
    NTSTATUS status;
    if (length < sizeof(cookie) || length > sizeof(cookie) + UDP_MAX_PAYLOAD)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&cookie, input, sizeof(cookie));
    KeAcquireSpinLock(&LeaseLock, &irql);
    active = FindUDPFlow(cookie);
    if (CurrentLease.Deadline <= KeQueryInterruptTime() || active == NULL || !active->HasEndpoint) {
        KeReleaseSpinLock(&LeaseLock, irql);
        return STATUS_NOT_FOUND;
    }
    flow = *active;
    KeReleaseSpinLock(&LeaseLock, irql);
    if (InterlockedIncrement(&UDPInFlight) > UDP_MAX_INFLIGHT) {
        InterlockedDecrement(&UDPInFlight);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    size = length - (ULONG)sizeof(cookie);
    total = (flow.IPv6 ? 40u : 20u) + UDP_HEADER_SIZE + size;
    packet = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)FIELD_OFFSET(UDP_INJECTION, Data) + total, PROXY_TAG);
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (packet == NULL)
        goto Fail;
    BuildUDPReply(&flow, packet->Data, input + sizeof(cookie), size);
    packet->Mdl = IoAllocateMdl(packet->Data, total, FALSE, FALSE, NULL);
    if (packet->Mdl == NULL)
        goto Fail;
    MmBuildMdlForNonPagedPool(packet->Mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(UDPPool, 0, 0, packet->Mdl, 0, total, &list);
    if (!NT_SUCCESS(status))
        goto Fail;
    status = FwpsInjectTransportReceiveAsync0(UDPInjection, NULL, NULL, 0, flow.IPv6 ? AF_INET6 : AF_INET,
        flow.Compartment, flow.Interface, flow.SubInterface, list, FreeUDPInjection, packet);
    if (NT_SUCCESS(status))
        return status;

Fail:
    FreeUDPInjection(packet, list, FALSE);
    return status;
}

static NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR written = 0;
    UNREFERENCED_PARAMETER(device);

    if (stack->MajorFunction == IRP_MJ_CLOSE) {
        status = STATUS_SUCCESS;
        goto Complete;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Complete;
    }
    KeWaitForSingleObject(&ManagementGate, Executive, KernelMode, FALSE, NULL);
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        if (OwnerFile != NULL || Engine != NULL || stack->FileObject->FileName.Length != 0) {
            status = STATUS_DEVICE_BUSY;
        } else {
            OwnerFile = stack->FileObject;
            OwnerProcess = IoGetRequestorProcess(irp);
            ObReferenceObject(OwnerProcess);
            status = STATUS_SUCCESS;
        }
        break;
    case IRP_MJ_CLEANUP:
        status = STATUS_SUCCESS;
        if (stack->FileObject == OwnerFile) {
            status = Disarm();
            OwnerFile = NULL;
            ObDereferenceObject(OwnerProcess);
            OwnerProcess = NULL;
        }
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (stack->FileObject != OwnerFile || irp->RequestorMode != UserMode ||
            IoGetRequestorProcess(irp) != OwnerProcess) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        {
            const ULONG length = stack->Parameters.DeviceIoControl.InputBufferLength;
            const UINT32 *buffer = irp->AssociatedIrp.SystemBuffer;
            switch (stack->Parameters.DeviceIoControl.IoControlCode) {
            case PROXY_ARM:
                status = buffer != NULL && ValidRegistration((const PROXY_REGISTRATION *)buffer, length)
                    ? Arm((const PROXY_REGISTRATION *)buffer) : STATUS_INVALID_PARAMETER;
                break;
            case PROXY_HEARTBEAT:
            case PROXY_DISARM:
                if (buffer == NULL || length != sizeof(*buffer) || *buffer != PROXY_VERSION) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    status = stack->Parameters.DeviceIoControl.IoControlCode == PROXY_HEARTBEAT ? Renew() : Disarm();
                }
                break;
            case PROXY_READ_UDP:
                if (length == 0 && buffer != NULL)
                    status = ReadUDP(irp->AssociatedIrp.SystemBuffer,
                        stack->Parameters.DeviceIoControl.OutputBufferLength, &written);
                break;
            case PROXY_REPLY_UDP:
                if (buffer != NULL)
                    status = ReplyUDP(irp->AssociatedIrp.SystemBuffer, length);
                break;
            case PROXY_UDP_DROPS:
                if (length == 0 && buffer != NULL &&
                    stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(UDPDrops)) {
                    KIRQL irql;
                    KeAcquireSpinLock(&LeaseLock, &irql);
                    *(UINT64 *)irp->AssociatedIrp.SystemBuffer = UDPDrops;
                    KeReleaseSpinLock(&LeaseLock, irql);
                    written = sizeof(UDPDrops);
                    status = STATUS_SUCCESS;
                }
                break;
            }
        }
        break;
    }
    KeSetEvent(&ManagementGate, IO_NO_INCREMENT, FALSE);

Complete:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = written;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static VOID DriverUnload(PDRIVER_OBJECT driver)
{
    (VOID)Disarm();
    for (UINT32 i = 0; i < 2; ++i) {
        if (UDPFlowCallout[i] != 0)
            (VOID)FwpsCalloutUnregisterById0(UDPFlowCallout[i]);
        if (UDPDataCallout[i] != 0)
            (VOID)FwpsCalloutUnregisterById0(UDPDataCallout[i]);
    }
    if (UDPInjection != NULL)
        (VOID)FwpsInjectionHandleDestroy0(UDPInjection);
    if (UDPPool != NULL)
        NdisFreeNetBufferListPool(UDPPool);
    if (Callout6 != 0)
        (VOID)FwpsCalloutUnregisterById0(Callout6);
    if (Callout4 != 0)
        (VOID)FwpsCalloutUnregisterById0(Callout4);
    if (RedirectHandle != NULL)
        FwpsRedirectHandleDestroy0(RedirectHandle);
    IoDeleteSymbolicLink(&SymbolicLink);
    IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    PDEVICE_OBJECT device;
    FWPS_CALLOUT1 callout = {0};
    NET_BUFFER_LIST_POOL_PARAMETERS pool = {0};
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);

    KeInitializeSpinLock(&LeaseLock);
    KeInitializeEvent(&ManagementGate, SynchronizationEvent, TRUE);
    KeInitializeEvent(&UDPFlowsDrained, NotificationEvent, TRUE);
    InitializeListHead(&UDPQueue);
    status = IoCreateDeviceSecure(driver, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                                  TRUE, &sddl, &DeviceClass, &device);
    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    status = FwpsRedirectHandleCreate0(&ProviderKey, 0, &RedirectHandle);
    if (!NT_SUCCESS(status))
        goto Fail;
    callout.calloutKey = Callout4Key;
    callout.classifyFn = Classify;
    callout.notifyFn = Notify;
    status = FwpsCalloutRegister1(device, &callout, &Callout4);
    if (!NT_SUCCESS(status))
        goto Fail;
    callout.calloutKey = Callout6Key;
    status = FwpsCalloutRegister1(device, &callout, &Callout6);
    if (!NT_SUCCESS(status))
        goto Fail;

    pool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    pool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    pool.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    pool.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    pool.fAllocateNetBuffer = TRUE;
    pool.PoolTag = PROXY_TAG;
    UDPPool = NdisAllocateNetBufferListPool(NULL, &pool);
    if (UDPPool == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    status = FwpsInjectionHandleCreate0(AF_UNSPEC, FWPS_INJECTION_TYPE_TRANSPORT, &UDPInjection);
    if (!NT_SUCCESS(status))
        goto Fail;
    for (UINT32 i = 0; i < 2; ++i) {
        callout.calloutKey = UDPFlowKey[i];
        callout.classifyFn = ClassifyUDPFlow;
        callout.flowDeleteFn = NULL;
        status = FwpsCalloutRegister1(device, &callout, &UDPFlowCallout[i]);
        if (!NT_SUCCESS(status))
            goto Fail;
        callout.calloutKey = UDPDataKey[i];
        callout.classifyFn = ClassifyUDPData;
        callout.flowDeleteFn = DeleteUDPFlow;
        status = FwpsCalloutRegister1(device, &callout, &UDPDataCallout[i]);
        if (!NT_SUCCESS(status))
            goto Fail;
    }

    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[IRP_MJ_CREATE] = Dispatch;
    driver->MajorFunction[IRP_MJ_CLEANUP] = Dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

Fail:
    DriverUnload(driver);
    return status;
}
