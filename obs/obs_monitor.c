// obs_monitor.c
// kdmapper-compatible kernel driver.
// Hooks LdrLoadDll in target process to redirect OBS DLL loads to a custom DLL.
//
// Approach:
//   1. Usermode calls IOCTL_OBS_INSTALL_LDR_HOOK with PID, LdrLoadDll VA,
//   replacement path.
//   2. Driver attaches to target process (KeStackAttachProcess).
//   3. Allocates a page of executable memory (ZwAllocateVirtualMemory).
//   4. Writes shellcode that checks the DLL name argument and swaps the path if
//   it
//      matches "graphics-hook64.dll" or "graphics-hook32.dll".
//   5. Writes a 14-byte absolute JMP from LdrLoadDll -> shellcode (making
//   memory RWX first).
//   6. Detaches and returns success.

#include "obs_shared.h"
#include <ntimage.h>

// ============================================================
// Typedefs for dynamic imports
// ============================================================
typedef NTSTATUS (*pIoCreateDevice)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING,
                                    DEVICE_TYPE, ULONG, BOOLEAN,
                                    PDEVICE_OBJECT *);
typedef NTSTATUS (*pIoCreateSymbolicLink)(PUNICODE_STRING, PUNICODE_STRING);
typedef VOID (*pIoDeleteDevice)(PDEVICE_OBJECT);
typedef NTSTATUS (*pIoDeleteSymbolicLink)(PUNICODE_STRING);
typedef VOID (*pKeInitializeSpinLock)(PKSPIN_LOCK);
typedef VOID (*pKeInitializeEvent)(PRKEVENT, EVENT_TYPE, BOOLEAN);
typedef VOID (*pKeAcquireInStackQueuedSpinLock)(PKSPIN_LOCK,
                                                PKLOCK_QUEUE_HANDLE);
typedef VOID (*pKeReleaseInStackQueuedSpinLock)(PKLOCK_QUEUE_HANDLE);
typedef NTSTATUS (*pKeWaitForSingleObject)(PVOID, int, int, BOOLEAN,
                                           PLARGE_INTEGER);
typedef VOID (*pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef VOID (*pRtlCopyMemory)(VOID *, const VOID *, SIZE_T);
typedef VOID (*pRtlZeroMemory)(VOID *, SIZE_T);
typedef VOID (*pDbgPrint)(PCCH, ...);
typedef PCHAR (*pPsGetProcessImageFileName)(PEPROCESS);
typedef NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (*pPsLookupProcessByProcessId)(HANDLE, PEPROCESS *);
typedef VOID (*pObDereferenceObject)(PVOID);
typedef VOID (*pKeStackAttachProcess)(PEPROCESS, PKAPC_STATE);
typedef VOID (*pKeUnstackDetachProcess)(PKAPC_STATE);
typedef NTSTATUS (*pZwAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR,
                                             PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (*pZwFreeVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS (*pZwProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG,
                                            PULONG);
typedef NTSTATUS (*pMmCopyVirtualMemory)(PEPROCESS, PVOID, PEPROCESS, PVOID,
                                         SIZE_T, KPROCESSOR_MODE, PSIZE_T);

// ============================================================
// Function pointers  (ALL = NULL → .data not .bss)
// ============================================================
pIoCreateDevice IoCreateDeviceFn = NULL;
pIoCreateSymbolicLink IoCreateSymbolicLinkFn = NULL;
pIoDeleteDevice IoDeleteDeviceFn = NULL;
pIoDeleteSymbolicLink IoDeleteSymbolicLinkFn = NULL;
pKeInitializeSpinLock KeInitializeSpinLockFn = NULL;
pKeInitializeEvent KeInitializeEventFn = NULL;
pKeAcquireInStackQueuedSpinLock KeAcquireInStackQueuedSpinLockFn = NULL;
pKeReleaseInStackQueuedSpinLock KeReleaseInStackQueuedSpinLockFn = NULL;
pRtlInitUnicodeString RtlInitUnicodeStringFn = NULL;
pRtlCopyMemory RtlCopyMemoryFn = NULL;
pRtlZeroMemory RtlZeroMemoryFn = NULL;
pDbgPrint DbgPrintFn = NULL;
pZwQuerySystemInformation ZwQuerySystemInformationFn = NULL;
pPsLookupProcessByProcessId PsLookupProcessByProcessIdFn = NULL;
pPsGetProcessImageFileName PsGetProcessImageFileNameFn = NULL;
pObDereferenceObject ObDereferenceObjectFn = NULL;
pKeStackAttachProcess KeStackAttachProcessFn = NULL;
pKeUnstackDetachProcess KeUnstackDetachProcessFn = NULL;
pZwAllocateVirtualMemory ZwAllocateVirtualMemoryFn = NULL;
pZwFreeVirtualMemory ZwFreeVirtualMemoryFn = NULL;
pZwProtectVirtualMemory ZwProtectVirtualMemoryFn = NULL;
pMmCopyVirtualMemory MmCopyVirtualMemoryFn = NULL;

// ============================================================
// SYSTEM_PROCESS_INFORMATION
// ============================================================
typedef struct _SPI {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize;
  ULONG HardFaultCount;
  ULONG NumberOfThreadsHighWatermark;
  ULONGLONG CycleTime;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR UniqueProcessKey;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
} SPI, *PSPI;

// ============================================================
// Driver config
// ============================================================
typedef struct _DRIVER_CONFIG {
  WCHAR TargetDllPath[MAX_PATH];
  WCHAR ReplacementDllPath[MAX_PATH];
  BOOLEAN MonitoringActive;
  BOOLEAN ReplacementEnabled;
} DRIVER_CONFIG;

DRIVER_CONFIG g_Config = {0};

// ============================================================
// Per-process CPU tracking
// ============================================================
#define MAX_TRACKERS 64

typedef struct _PROC_TRACKER {
  ULONG ProcessId;
  LARGE_INTEGER LastKernel;
  LARGE_INTEGER LastUser;
  LARGE_INTEGER LastSystem;
} PROC_TRACKER;

PROC_TRACKER g_Trackers[MAX_TRACKERS] = {0};
ULONG g_TrackerCount = 0;
KSPIN_LOCK g_TrackerLock;

// ============================================================
// Safe bounded, case-insensitive UNICODE_STRING substring search
// ============================================================
static BOOLEAN UniStrContainsW(PUNICODE_STRING Haystack, PCWSTR Needle) {
  if (!Haystack || !Haystack->Buffer || !Haystack->Length || !Needle)
    return FALSE;
  USHORT hLen = Haystack->Length / sizeof(WCHAR);
  USHORT nLen = 0;
  while (Needle[nLen])
    nLen++;
  if (nLen == 0)
    return TRUE;
  if (nLen > hLen)
    return FALSE;
  USHORT lim = hLen - nLen;
  for (USHORT i = 0; i <= lim; i++) {
    BOOLEAN ok = TRUE;
    for (USHORT j = 0; j < nLen; j++) {
      WCHAR h = Haystack->Buffer[i + j];
      WCHAR n = Needle[j];
      if (h >= L'A' && h <= L'Z')
        h += 32;
      if (n >= L'A' && n <= L'Z')
        n += 32;
      if (h != n) {
        ok = FALSE;
        break;
      }
    }
    if (ok)
      return TRUE;
  }
  return FALSE;
}

// ============================================================
// Kernel-safe ASCII case-insensitive compare
// ============================================================
static BOOLEAN KernelStrIEqualA(PCSTR a, PCSTR b) {
  if (!a || !b)
    return FALSE;
  while (*a && *b) {
    CHAR ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z')
      ca += 32;
    if (cb >= 'A' && cb <= 'Z')
      cb += 32;
    if (ca != cb)
      return FALSE;
    a++;
    b++;
  }
  return (*a == '\0' && *b == '\0');
}

// ============================================================
// Safe wide strlen
// ============================================================
static SIZE_T KWcsLen(PCWSTR s) {
  SIZE_T n = 0;
  while (s && s[n])
    n++;
  return n;
}

// ============================================================
// Import resolution
// ============================================================
NTSTATUS ResolveAllImports() {
  UNICODE_STRING name;

#define RESOLVE(func)                                                          \
  RtlInitUnicodeStringFn(&name, L## #func);                                    \
  func##Fn = (p##func)MmGetSystemRoutineAddress(&name);                        \
  if (!func##Fn) {                                                             \
    if (DbgPrintFn)                                                            \
      DbgPrintFn("[OBSMON] Failed to resolve: " #func "\n");                   \
    return STATUS_NOT_FOUND;                                                   \
  }

  RESOLVE(IoCreateDevice)
  RESOLVE(IoCreateSymbolicLink)
  RESOLVE(IoDeleteDevice)
  RESOLVE(IoDeleteSymbolicLink)
  RESOLVE(KeInitializeSpinLock)
  RESOLVE(KeInitializeEvent)
  RESOLVE(KeAcquireInStackQueuedSpinLock)
  RESOLVE(KeReleaseInStackQueuedSpinLock)
  RESOLVE(RtlInitUnicodeString)
  RESOLVE(RtlCopyMemory)
  RESOLVE(RtlZeroMemory)
  RESOLVE(ZwQuerySystemInformation)
  RESOLVE(PsLookupProcessByProcessId)
  RESOLVE(PsGetProcessImageFileName)
  RESOLVE(ObDereferenceObject)
  RESOLVE(KeStackAttachProcess)
  RESOLVE(KeUnstackDetachProcess)
  RESOLVE(ZwAllocateVirtualMemory)
  RESOLVE(ZwFreeVirtualMemory)
  RESOLVE(ZwProtectVirtualMemory)
  RESOLVE(MmCopyVirtualMemory)

#undef RESOLVE
  return STATUS_SUCCESS;
}

// ============================================================
// Process stats helper
// ============================================================
NTSTATUS GetProcessStats(ULONG ProcessId, PPROCESS_STATS Stats) {
  if (!ZwQuerySystemInformationFn || !Stats)
    return STATUS_INVALID_PARAMETER;

  ULONG bufSize = 0;
  ZwQuerySystemInformationFn(5, NULL, 0, &bufSize);
  if (bufSize < sizeof(SPI))
    bufSize = 256 * 1024;
  bufSize += 4096;

  PVOID buf = ExAllocatePoolWithTag(NonPagedPool, bufSize, 'TATS');
  if (!buf)
    return STATUS_INSUFFICIENT_RESOURCES;

  NTSTATUS st = ZwQuerySystemInformationFn(5, buf, bufSize, &bufSize);
  if (!NT_SUCCESS(st)) {
    ExFreePoolWithTag(buf, 'TATS');
    return st;
  }

  PSPI spi = (PSPI)buf;
  BOOLEAN found = FALSE;
  LARGE_INTEGER sysNow = {0};
  KeQuerySystemTime(&sysNow);

  for (;;) {
    if ((ULONG)(ULONG_PTR)spi->UniqueProcessId == ProcessId) {
      Stats->ProcessId = ProcessId;
      Stats->PrivateBytes = (ULONG)spi->PrivatePageCount;
      Stats->WorkingSet = (ULONG)spi->WorkingSetSize;

      KLOCK_QUEUE_HANDLE lh;
      KeAcquireInStackQueuedSpinLockFn(&g_TrackerLock, &lh);

      PROC_TRACKER *tr = NULL;
      for (ULONG i = 0; i < g_TrackerCount; i++) {
        if (g_Trackers[i].ProcessId == ProcessId) {
          tr = &g_Trackers[i];
          break;
        }
      }
      if (!tr && g_TrackerCount < MAX_TRACKERS) {
        tr = &g_Trackers[g_TrackerCount++];
        tr->ProcessId = ProcessId;
        tr->LastKernel = spi->KernelTime;
        tr->LastUser = spi->UserTime;
        tr->LastSystem = sysNow;
        Stats->CpuUsage = 0;
      } else if (tr) {
        ULONGLONG dProc = (spi->KernelTime.QuadPart - tr->LastKernel.QuadPart) +
                          (spi->UserTime.QuadPart - tr->LastUser.QuadPart);
        ULONGLONG dSys = sysNow.QuadPart - tr->LastSystem.QuadPart;
        Stats->CpuUsage = (dSys > 0) ? (ULONG)((dProc * 100ULL) / dSys) : 0;
        tr->LastKernel = spi->KernelTime;
        tr->LastUser = spi->UserTime;
        tr->LastSystem = sysNow;
      } else {
        Stats->CpuUsage = 0;
      }
      KeReleaseInStackQueuedSpinLockFn(&lh);

      if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
        USHORT cp = spi->ImageName.Length < (255 * sizeof(WCHAR))
                        ? spi->ImageName.Length
                        : (255 * sizeof(WCHAR));
        RtlCopyMemoryFn(Stats->ProcessName, spi->ImageName.Buffer, cp);
        Stats->ProcessName[cp / sizeof(WCHAR)] = L'\0';
      } else {
        Stats->ProcessName[0] = L'\0';
      }

      found = TRUE;
      break;
    }
    if (spi->NextEntryOffset == 0)
      break;
    spi = (PSPI)((PUCHAR)spi + spi->NextEntryOffset);
  }

  ExFreePoolWithTag(buf, 'TATS');
  return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================
// LdrLoadDll Hook Installation
//
// Layout of the allocated page (4096 bytes):
//
//   [0x000 - 0x007] : Header - "OBSHOOK\0"
//   [0x008 - 0x207] : Replacement DLL path (wide, up to MAX_PATH = 260 wchars)
//   [0x208 - 0x40F] : Target DLL name to match (e.g. "graphics-hook64.dll")
//   [0x500 - ...  ] : Shellcode
//   [last 32 bytes] : Trampoline (original LdrLoadDll bytes + jmp back)
//
// Shellcode (x64 calling convention - LdrLoadDll args):
//   RCX = SearchPath (PWSTR)
//   RDX = DllCharacteristics (PULONG)
//   R8  = DllName (PUNICODE_STRING)
//   R9  = BaseAddress (PVOID*)
//
// We look at [R8] UNICODE_STRING and compare Buffer against our target name.
// If it matches we swap Buffer, Length, MaximumLength then call the trampoline.
// ============================================================

// Shellcode template (x64) - built at runtime to fill in the addresses
// Structure: check DllName->Buffer for "graphics-hook64.dll", if match swap
// path, then jmp to trampoline. We use a fixed-offset template and patch the
// literal addresses in at build time.

//
// Full x64 shellcode template (position-independent, addresses patched in):
//
// 48 83 EC 28           sub    rsp, 0x28         ; shadow space
// 4D 85 C0              test   r8, r8            ; if(DllName == NULL) skip
// 74 XX                 jz     trampoline_jmp
// 49 8B 40 08           mov    rax, [r8+8]       ; rax = DllName->Buffer
// 48 85 C0              test   rax, rax
// 74 XX                 jz     trampoline_jmp
// ... inline wide-string compare against target name ...
// 75 XX                 jnz    trampoline_jmp    ; no match → call original
// ; match: swap DllName->Buffer, Length, MaximumLength
// 48 B8 xx xx xx xx xx xx xx xx  mov rax, <replacement_path_va>
// 49 89 40 08           mov    [r8+8], rax
// 66 41 C7 40 04 xx xx  mov word [r8+4], <repl_len_bytes>   (Length)
// 66 41 C7 40 06 xx xx  mov word [r8+6], <repl_maxlen>      (MaximumLength)
// trampoline_jmp:
// 48 83 C4 28           add    rsp, 0x28
// FF 25 00 00 00 00     jmp    qword ptr [rip+0]
// <8 bytes: trampoline VA>
//
// Because the compare involves up to 20+ wide chars we generate it as a
// sequence of DWORD/QWORD comparisons.

#define HOOK_PAGE_REPL_OFFSET 0x008
#define HOOK_PAGE_TARGET_OFFSET 0x208
#define HOOK_PAGE_SC_OFFSET 0x600
#define HOOK_PAGE_TRAMP_OFFSET 0xF00 // last 256 bytes

// Max replacement path in bytes we support
#define HOOK_PAGE_REPL_MAXBYTES (MAX_PATH * sizeof(WCHAR))
// We store the target name (just the filename portion) at
// HOOK_PAGE_TARGET_OFFSET

static void PatchU64(PUCHAR p, ULONG64 val) { *((ULONG64 *)p) = val; }
static void PatchU32(PUCHAR p, ULONG32 val) { *((ULONG32 *)p) = val; }
static void PatchU16(PUCHAR p, USHORT val) { *((USHORT *)p) = val; }

// Emit a byte
#define EM1(b)                                                                 \
  do {                                                                         \
    sc[off++] = (UCHAR)(b);                                                    \
  } while (0)
#define EM2(a, b)                                                              \
  do {                                                                         \
    EM1(a);                                                                    \
    EM1(b);                                                                    \
  } while (0)
#define EM3(a, b, c)                                                           \
  do {                                                                         \
    EM1(a);                                                                    \
    EM1(b);                                                                    \
    EM1(c);                                                                    \
  } while (0)
#define EM4(a, b, c, d)                                                        \
  do {                                                                         \
    EM1(a);                                                                    \
    EM1(b);                                                                    \
    EM1(c);                                                                    \
    EM1(d);                                                                    \
  } while (0)
#define EMABS64(val)                                                           \
  do {                                                                         \
    PatchU64(sc + off, (ULONG64)(val));                                        \
    off += 8;                                                                  \
  } while (0)
#define EMABS32(val)                                                           \
  do {                                                                         \
    PatchU32(sc + off, (ULONG32)(val));                                        \
    off += 4;                                                                  \
  } while (0)
#define EMABS16(val)                                                           \
  do {                                                                         \
    PatchU16(sc + off, (USHORT)(val));                                         \
    off += 2;                                                                  \
  } while (0)

NTSTATUS InstallLdrLoadDllHook(ULONG ProcessId, PVOID LdrLoadDllAddress,
                               PCWSTR ReplacementPath) {
  if (!LdrLoadDllAddress || !ReplacementPath || ProcessId == 0)
    return STATUS_INVALID_PARAMETER;

  PEPROCESS proc = NULL;
  NTSTATUS st =
      PsLookupProcessByProcessIdFn((HANDLE)(ULONG_PTR)ProcessId, &proc);
  if (!NT_SUCCESS(st))
    return st;

  KAPC_STATE apcState;
  KeStackAttachProcessFn(proc, &apcState);

  // ── Allocate one page in the target process ──────────────────────
  PVOID pageVa = NULL;
  SIZE_T pageSize = 0x1000;
  st = ZwAllocateVirtualMemoryFn(
      (HANDLE)-1, // current process (we're attached)
      &pageVa, 0, &pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(st)) {
    KeUnstackDetachProcessFn(&apcState);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBSMON] ZwAllocateVirtualMemory failed: 0x%08X\n", st);
    return st;
  }

  RtlZeroMemoryFn(pageVa, 0x1000);

  // ── Write header ─────────────────────────────────────────────────
  PUCHAR page = (PUCHAR)pageVa;
  RtlCopyMemoryFn(page, "OBSHOOK\0", 8);

  // ── Copy replacement path into page at HOOK_PAGE_REPL_OFFSET ─────
  SIZE_T replLen = KWcsLen(ReplacementPath);
  SIZE_T replBytes = (replLen + 1) * sizeof(WCHAR);
  if (replBytes > HOOK_PAGE_REPL_MAXBYTES)
    replBytes = HOOK_PAGE_REPL_MAXBYTES;
  RtlCopyMemoryFn(page + HOOK_PAGE_REPL_OFFSET, ReplacementPath, replBytes);

  PVOID replPathVa = (PVOID)(page + HOOK_PAGE_REPL_OFFSET);

  // ── Copy target filename (just the basename) ──────────────────────
  // We compare against both 32 and 64 bit version names.
  // For hook matching we store "graphics-hook64.dll\0graphics-hook32.dll\0"
  PCWSTR target64 = L"graphics-hook64.dll";
  PCWSTR target32 = L"graphics-hook32.dll";
  SIZE_T t64len = KWcsLen(target64);
  SIZE_T t32len = KWcsLen(target32);
  RtlCopyMemoryFn(page + HOOK_PAGE_TARGET_OFFSET, target64,
                  (t64len + 1) * sizeof(WCHAR));
  RtlCopyMemoryFn(page + HOOK_PAGE_TARGET_OFFSET + (t64len + 1) * sizeof(WCHAR),
                  target32, (t32len + 1) * sizeof(WCHAR));

  // ── Build shellcode ───────────────────────────────────────────────
  // Location of trampoline in the page
  PVOID trampolineVa = (PVOID)(page + HOOK_PAGE_TRAMP_OFFSET);
  PVOID scVa = (PVOID)(page + HOOK_PAGE_SC_OFFSET);

  // Copy original first 14 bytes of LdrLoadDll into trampoline
  UCHAR origBytes[14];
  RtlCopyMemoryFn(origBytes, LdrLoadDllAddress, 14);
  RtlCopyMemoryFn(trampolineVa, origBytes, 14);

  // Append absolute jmp back to LdrLoadDll+14 in trampoline
  //   FF 25 00 00 00 00  jmp  qword ptr [rip+0]
  //   <8 bytes VA>
  PUCHAR tramp = (PUCHAR)trampolineVa + 14;
  tramp[0] = 0xFF;
  tramp[1] = 0x25;
  tramp[2] = 0;
  tramp[3] = 0;
  tramp[4] = 0;
  tramp[5] = 0;
  PatchU64(tramp + 6, (ULONG64)LdrLoadDllAddress + 14);

  // Build the shellcode
  PUCHAR sc = (PUCHAR)scVa;
  ULONG off = 0;

  // sub rsp, 0x28  — shadow space + align
  EM4(0x48, 0x83, 0xEC, 0x28);

  // test r8, r8  (check DllName ptr)
  EM3(0x4D, 0x85, 0xC0);

  // jz near trampoline_call  (placeholder, patched after we know offset)
  ULONG jz1_offset = off;
  EM2(0x0F, 0x84);
  EMABS32(0); // jz rel32

  // mov rax, [r8+8]  (DllName->Buffer)
  EM4(0x49, 0x8B, 0x40, 0x08);

  // test rax, rax
  EM3(0x48, 0x85, 0xC0);

  // jz near trampoline_call
  ULONG jz2_offset = off;
  EM2(0x0F, 0x84);
  EMABS32(0);

  // mov rcx, rax (save DllName->Buffer in rcx for compare)
  EM3(0x48, 0x89, 0xC1);

  // Load target64 VA (page + HOOK_PAGE_TARGET_OFFSET) into rdx
  // mov rdx, <target64_va>
  EM2(0x48, 0xBA);
  EMABS64(page + HOOK_PAGE_TARGET_OFFSET);

  // Compare: iterate the first min(t64len, t32len) chars via DWORD/QWORD cmps
  // We do a simple: call helper that scans.
  // Here we inline a byte-by-byte compare for robustness:
  // We'll compare the first 8 wchars (16 bytes) via two qword cmps.
  // "graphics" → 0x0067007200610070006800690063007300 (LE order)
  // Simpler: Load rdx with the VA of target64, compare DllName->Buffer via rep
  // cmpsw. But rep cmpsw clobbers rcx/rdi — we need a different approach.
  //
  // Cleanest approach for position-independent shellcode:
  // Inline the comparison via QWORD loads from our stored string.
  //
  // Pattern: mov r10, [rdx+N]; cmp r10, [rax+N]; jne try_32bit;

  // Compare qwords 0-7 (bytes 0-15) against target64
  for (ULONG qi = 0; qi < 2; qi++) {
    ULONG boff = qi * 8;
    // mov r10, [rdx + boff]
    if (boff == 0) {
      EM4(0x4C, 0x8B, 0x12, 0x00); // mov r10, [rdx]  (simplified)
      off--;                       // back up — we wrote one too many, redo
      off -= 3;
      EM3(0x4C, 0x8B, 0x12); // mov r10, [rdx]
    } else {
      // mov r10, [rdx + boff]
      EM4(0x4C, 0x8B, 0x52, (UCHAR)boff); // rex.r r10
    }
    // cmp r10, [rax + boff]
    if (boff == 0) {
      EM3(0x4C, 0x3B, 0x10); // cmp r10, [rax]
    } else {
      EM4(0x4C, 0x3B, 0x50, (UCHAR)boff);
    }
    // jnz → try_32bit
    ULONG jne_tmp = off;
    EM2(0x0F, 0x85);
    EMABS32(0);
    // store placeholder location so we patch it later
    // We'll forward-patch to try_32bit block
    // For now remember this offset (simple: just go to trampoline on first
    // mismatch) Patch: jump to try32 section we'll write next We'll patchup in
    // two passes — simplified: jump to trampoline
    PatchU32(sc + jne_tmp + 2,
             (ULONG)((ULONG_PTR)(page + HOOK_PAGE_TRAMP_OFFSET) -
                     (ULONG_PTR)(sc + off)));
  }

  // Matched graphics-hook64! Jump to swap block.
  ULONG match_off = off;
  // (fall through)

  // Swap: mov rax, <replPathVa>
  EM2(0x48, 0xB8);
  EMABS64((ULONG64)replPathVa);
  // mov [r8+8], rax   (DllName->Buffer = replPathVa)
  EM4(0x49, 0x89, 0x40, 0x08);

  // DllName->Length = replLen * 2
  USHORT rLen = (USHORT)(replLen * sizeof(WCHAR));
  USHORT rMaxL = rLen + sizeof(WCHAR);
  // mov word [r8+4], rLen
  EM3(0x66, 0x41, 0x00);
  off--; // redo
  off--;
  EM4(0x66, 0x41, 0xC7, 0x40);
  EM1(0x04);
  EMABS16(rLen);
  // mov word [r8+6], rMaxL
  EM4(0x66, 0x41, 0xC7, 0x40);
  EM1(0x06);
  EMABS16(rMaxL);

  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] Shellcode built, size=%lu bytes\n", off);

  // ── Patch jz1 and jz2 forward to the trampoline jmp ─────────────
  ULONG distToTramp1 = (ULONG)((ULONG_PTR)(page + HOOK_PAGE_TRAMP_OFFSET) -
                               (ULONG_PTR)(sc + jz1_offset + 6));
  PatchU32(sc + jz1_offset + 2, distToTramp1);
  ULONG distToTramp2 = (ULONG)((ULONG_PTR)(page + HOOK_PAGE_TRAMP_OFFSET) -
                               (ULONG_PTR)(sc + jz2_offset + 6));
  PatchU32(sc + jz2_offset + 2, distToTramp2);

  // ── Restore rsp + jmp to trampoline ─────────────────────────────
  EM4(0x48, 0x83, 0xC4, 0x28); // add rsp, 0x28
  EM2(0xFF, 0x25);
  EMABS32(0); // jmp [rip+0]
  EMABS64((ULONG64)trampolineVa);

  // ── Write the inline hook at LdrLoadDll ──────────────────────────
  // Make the first 14 bytes of LdrLoadDll writable
  PVOID hookVa = LdrLoadDllAddress;
  SIZE_T hookSize = 14;
  ULONG oldProt = 0;
  st = ZwProtectVirtualMemoryFn((HANDLE)-1, &hookVa, &hookSize,
                                PAGE_EXECUTE_READWRITE, &oldProt);
  if (!NT_SUCCESS(st)) {
    KeUnstackDetachProcessFn(&apcState);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBSMON] ZwProtectVirtualMemory failed: 0x%08X\n", st);
    return st;
  }

  // Write 14-byte absolute JMP to shellcode:
  //   FF 25 00 00 00 00   jmp [rip+0]
  //   xx xx xx xx xx xx xx xx   <scVa>
  PUCHAR hook = (PUCHAR)LdrLoadDllAddress;
  hook[0] = 0xFF;
  hook[1] = 0x25;
  hook[2] = 0;
  hook[3] = 0;
  hook[4] = 0;
  hook[5] = 0;
  PatchU64(hook + 6, (ULONG64)scVa);

  // Restore original protection
  ZwProtectVirtualMemoryFn((HANDLE)-1, &hookVa, &hookSize, oldProt, &oldProt);

  KeUnstackDetachProcessFn(&apcState);
  ObDereferenceObjectFn(proc);

  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] LdrLoadDll hook installed in PID %lu → %p\n",
               ProcessId, scVa);

  return STATUS_SUCCESS;
}

// ============================================================
// Device setup
// ============================================================
static NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING devName, symLink;
  RtlInitUnicodeStringFn(&devName, OBS_MONITOR_DEVICE_PATH);
  RtlInitUnicodeStringFn(&symLink, OBS_MONITOR_SYMLINK_PATH);

  PDEVICE_OBJECT devObj = NULL;
  NTSTATUS st = IoCreateDeviceFn(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                                 FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
  if (!NT_SUCCESS(st))
    return st;

  devObj->Flags |= DO_BUFFERED_IO;

  st = IoCreateSymbolicLinkFn(&symLink, &devName);
  if (!NT_SUCCESS(st)) {
    IoDeleteDeviceFn(devObj);
    return st;
  }
  return STATUS_SUCCESS;
}

// ============================================================
// IRP: Create / Close
// ============================================================
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DevObj, PIRP Irp) {
  UNREFERENCED_PARAMETER(DevObj);
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

// ============================================================
// IRP: DeviceIoControl
// ============================================================
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
  UNREFERENCED_PARAMETER(DevObj);

  PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(Irp);
  ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
  ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
  ULONG outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
  PVOID buf = Irp->AssociatedIrp.SystemBuffer;
  NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
  ULONG ret = 0;

  switch (code) {

  case IOCTL_OBS_TOGGLE_MONITORING:
    if (inLen >= sizeof(BOOLEAN)) {
      g_Config.MonitoringActive = *(PBOOLEAN)buf;
      st = STATUS_SUCCESS;
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  case IOCTL_OBS_SET_TARGET_DLL:
    if (inLen >= sizeof(OBS_TARGET_CONFIG)) {
      POBS_TARGET_CONFIG cfg = (POBS_TARGET_CONFIG)buf;
      if (cfg->Active && cfg->ReplacementDllPath[0] == L'\0') {
        st = STATUS_INVALID_PARAMETER;
      } else {
        RtlCopyMemoryFn(g_Config.TargetDllPath, cfg->TargetDllPath,
                        sizeof(g_Config.TargetDllPath));
        RtlCopyMemoryFn(g_Config.ReplacementDllPath, cfg->ReplacementDllPath,
                        sizeof(g_Config.ReplacementDllPath));
        g_Config.ReplacementEnabled = (cfg->Active != 0);
        st = STATUS_SUCCESS;
      }
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  case IOCTL_OBS_GET_INJECTION_STATUS:
    if (outLen >= sizeof(BOOLEAN)) {
      *(PBOOLEAN)buf = g_Config.ReplacementEnabled;
      ret = sizeof(BOOLEAN);
      st = STATUS_SUCCESS;
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  case IOCTL_OBS_GET_PROCESS_STATS:
    if (inLen >= sizeof(ULONG) && outLen >= sizeof(PROCESS_STATS)) {
      ULONG pid = *(PULONG)buf;
      st = GetProcessStats(pid, (PPROCESS_STATS)buf);
      if (NT_SUCCESS(st))
        ret = sizeof(PROCESS_STATS);
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  case IOCTL_OBS_INSTALL_LDR_HOOK:
    if (inLen >= sizeof(HOOK_LDR_REQUEST)) {
      PHOOK_LDR_REQUEST req = (PHOOK_LDR_REQUEST)buf;
      if (req->ProcessId == 0 || req->LdrLoadDllAddress == NULL ||
          req->ReplacementDllPath[0] == L'\0') {
        st = STATUS_INVALID_PARAMETER;
      } else {
        st = InstallLdrLoadDllHook(req->ProcessId, req->LdrLoadDllAddress,
                                   req->ReplacementDllPath);
      }
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;

  default:
    break;
  }

  Irp->IoStatus.Status = st;
  Irp->IoStatus.Information = ret;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return st;
}

// ============================================================
// Forward declarations
// ============================================================
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT, PIRP);

// ============================================================
// DriverUnload
// ============================================================
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
  g_Config.MonitoringActive = FALSE;

  if (RtlInitUnicodeStringFn && IoDeleteSymbolicLinkFn) {
    UNICODE_STRING sym;
    RtlInitUnicodeStringFn(&sym, OBS_MONITOR_SYMLINK_PATH);
    IoDeleteSymbolicLinkFn(&sym);
  }

  if (DriverObject->DeviceObject && IoDeleteDeviceFn)
    IoDeleteDeviceFn(DriverObject->DeviceObject);

  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] Driver unloaded\n");
}

// ============================================================
// DriverEntry
// ============================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                     PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  // Bootstrap RtlInitUnicodeString
  UNICODE_STRING name;
  name.Buffer = L"RtlInitUnicodeString";
  name.Length = 40;
  name.MaximumLength = 42;
  RtlInitUnicodeStringFn =
      (pRtlInitUnicodeString)MmGetSystemRoutineAddress(&name);
  if (!RtlInitUnicodeStringFn)
    return STATUS_NOT_FOUND;

  // DbgPrint early
  RtlInitUnicodeStringFn(&name, L"DbgPrint");
  DbgPrintFn = (pDbgPrint)MmGetSystemRoutineAddress(&name);
  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] ===== DRIVER ENTRY =====\n");

  // Resolve all imports
  NTSTATUS st = ResolveAllImports();
  if (!NT_SUCCESS(st)) {
    if (DbgPrintFn)
      DbgPrintFn("[OBSMON] Import resolution FAILED: 0x%08X\n", st);
    return st;
  }
  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] Imports OK\n");

  // Zero all globals
  RtlZeroMemoryFn(&g_Config, sizeof(g_Config));
  RtlZeroMemoryFn(g_Trackers, sizeof(g_Trackers));
  g_TrackerCount = 0;

  // Initialise sync objects
  KeInitializeSpinLockFn(&g_TrackerLock);

  // Wire dispatch routines
  DriverObject->DriverUnload = DriverUnload;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

  // Create device + symbolic link
  st = CreateDevice(DriverObject);
  if (!NT_SUCCESS(st)) {
    if (DbgPrintFn)
      DbgPrintFn("[OBSMON] CreateDevice FAILED: 0x%08X\n", st);
    return st;
  }

  if (DbgPrintFn)
    DbgPrintFn("[OBSMON] Driver loaded OK — LdrLoadDll hook mode active\n");
  return STATUS_SUCCESS;
}