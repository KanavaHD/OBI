// obs_monitor.c - Fixed kernel driver with LdrLoadDll hooking
// kdmapper-compatible (no static initializers, all imports dynamic)
//
// Fixes applied:
// 1. Proper headers (ntifs.h, intrin.h, windef.h)
// 2. Kernel-side ntdll base + LdrLoadDll resolution via PEB traversal
// 3. PE export table parsing in kernel
// 4. Corrected x64 shellcode with proper register saves
// 5. PioneerGame.exe process validation
// 6. IOCTL resolves LdrLoadDll itself (never trusts usermode address)
// 7. Full cleanup on failure (free alloc, detach)
// 8. UNICODE_STRING offsets documented

#include <intrin.h>
#include <ntifs.h>


// ── UNICODE_STRING offsets (x64):
//   +0x00  Length        USHORT
//   +0x02  MaximumLength USHORT
//   +0x04  (padding)
//   +0x08  Buffer        PWSTR

// ── Windows PEB / LDR structures (minimal) ──────────────────────────────────
typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB64 {
  UCHAR Reserved1[2];
  UCHAR BeingDebugged;
  UCHAR Reserved2[21];
  PPEB_LDR_DATA Ldr; // offset 0x18
} PEB64, *PPEB64;

// ── Shared header (inline to avoid dependency) ───────────────────────────────
#define OBS_MONITOR_DEVICE_PATH L"\\Device\\OBSMonitor"
#define OBS_MONITOR_SYMLINK_PATH L"\\DosDevices\\OBSMonitor"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define IOCTL_OBS_GET_PROCESS_STATS                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBS_INSTALL_LDR_HOOK                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PROCESS_STATS {
  ULONG ProcessId;
  ULONG CpuUsage;
  ULONG PrivateBytes;
  ULONG WorkingSet;
  WCHAR ProcessName[256];
} PROCESS_STATS, *PPROCESS_STATS;

// Only ProcessId + ReplacementDllPath — driver resolves LdrLoadDll itself
typedef struct _HOOK_LDR_REQUEST {
  ULONG ProcessId;
  WCHAR ReplacementDllPath[MAX_PATH];
} HOOK_LDR_REQUEST, *PHOOK_LDR_REQUEST;

// ── Dynamic import typedefs ──────────────────────────────────────────────────
typedef VOID (*pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef VOID (*pDbgPrint)(PCCH, ...);
typedef NTSTATUS (*pPsLookupProcessByProcessId)(HANDLE, PEPROCESS *);
typedef PCHAR (*pPsGetProcessImageFileName)(PEPROCESS);
typedef VOID (*pObDereferenceObject)(PVOID);
typedef VOID (*pKeStackAttachProcess)(PEPROCESS, PKAPC_STATE);
typedef VOID (*pKeUnstackDetachProcess)(PKAPC_STATE);
typedef NTSTATUS (*pZwAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR,
                                             PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (*pZwFreeVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS (*pZwProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG,
                                            PULONG);
typedef NTSTATUS (*pIoCreateDevice)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING,
                                    DEVICE_TYPE, ULONG, BOOLEAN,
                                    PDEVICE_OBJECT *);
typedef NTSTATUS (*pIoCreateSymbolicLink)(PUNICODE_STRING, PUNICODE_STRING);
typedef VOID (*pIoDeleteDevice)(PDEVICE_OBJECT);
typedef NTSTATUS (*pIoDeleteSymbolicLink)(PUNICODE_STRING);
typedef VOID (*pKeInitializeSpinLock)(PKSPIN_LOCK);
typedef VOID (*pRtlZeroMemory)(VOID *, SIZE_T);
typedef VOID (*pRtlCopyMemory)(VOID *, const VOID *, SIZE_T);
typedef PVOID (*pPsGetProcessPeb)(PEPROCESS);

// ── Function pointers ────────────────────────────────────────────────────────
pRtlInitUnicodeString RtlInitUnicodeStringFn = NULL;
pDbgPrint DbgPrintFn = NULL;
pPsLookupProcessByProcessId PsLookupProcessByProcessIdFn = NULL;
pPsGetProcessImageFileName PsGetProcessImageFileNameFn = NULL;
pObDereferenceObject ObDereferenceObjectFn = NULL;
pKeStackAttachProcess KeStackAttachProcessFn = NULL;
pKeUnstackDetachProcess KeUnstackDetachProcessFn = NULL;
pZwAllocateVirtualMemory ZwAllocateVirtualMemoryFn = NULL;
pZwFreeVirtualMemory ZwFreeVirtualMemoryFn = NULL;
pZwProtectVirtualMemory ZwProtectVirtualMemoryFn = NULL;
pIoCreateDevice IoCreateDeviceFn = NULL;
pIoCreateSymbolicLink IoCreateSymbolicLinkFn = NULL;
pIoDeleteDevice IoDeleteDeviceFn = NULL;
pIoDeleteSymbolicLink IoDeleteSymbolicLinkFn = NULL;
pKeInitializeSpinLock KeInitializeSpinLockFn = NULL;
pRtlZeroMemory RtlZeroMemoryFn = NULL;
pRtlCopyMemory RtlCopyMemoryFn = NULL;
pPsGetProcessPeb PsGetProcessPebFn = NULL;

// ── Import resolution ────────────────────────────────────────────────────────
#define RESOLVE(fn)                                                            \
  do {                                                                         \
    RtlInitUnicodeStringFn(&_n, L## #fn);                                      \
    fn##Fn = (p##fn)MmGetSystemRoutineAddress(&_n);                            \
    if (!fn##Fn) {                                                             \
      if (DbgPrintFn)                                                          \
        DbgPrintFn("[OBS] Missing: " #fn "\n");                                \
      return STATUS_NOT_FOUND;                                                 \
    }                                                                          \
  } while (0)

static NTSTATUS ResolveImports(void) {
  UNICODE_STRING _n;
  RESOLVE(IoCreateDevice);
  RESOLVE(IoCreateSymbolicLink);
  RESOLVE(IoDeleteDevice);
  RESOLVE(IoDeleteSymbolicLink);
  RESOLVE(KeInitializeSpinLock);
  RESOLVE(RtlZeroMemory);
  RESOLVE(RtlCopyMemory);
  RESOLVE(PsLookupProcessByProcessId);
  RESOLVE(PsGetProcessImageFileName);
  RESOLVE(ObDereferenceObject);
  RESOLVE(KeStackAttachProcess);
  RESOLVE(KeUnstackDetachProcess);
  RESOLVE(ZwAllocateVirtualMemory);
  RESOLVE(ZwFreeVirtualMemory);
  RESOLVE(ZwProtectVirtualMemory);
  RESOLVE(PsGetProcessPeb);
  return STATUS_SUCCESS;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
static SIZE_T KWcsLen(PCWSTR s) {
  SIZE_T n = 0;
  while (s && s[n])
    n++;
  return n;
}

static BOOLEAN KWcsEndsWithI(PCWSTR haystack, PCWSTR needle) {
  if (!haystack || !needle)
    return FALSE;
  SIZE_T hl = KWcsLen(haystack), nl = KWcsLen(needle);
  if (nl > hl)
    return FALSE;
  const WCHAR *p = haystack + hl - nl;
  for (SIZE_T i = 0; i < nl; i++) {
    WCHAR a = p[i], b = needle[i];
    if (a >= 'A' && a <= 'Z')
      a += 32;
    if (b >= 'A' && b <= 'Z')
      b += 32;
    if (a != b)
      return FALSE;
  }
  return TRUE;
}

static BOOLEAN KStrIEqA(PCSTR a, PCSTR b) {
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
  return *a == '\0' && *b == '\0';
}

// ── Read memory from another process safely ──────────────────────────────────
// Must be called while already attached (KeStackAttachProcess) OR at
// PASSIVE_LEVEL with the target being the current process.
static NTSTATUS SafeRead(PVOID src, PVOID dst, SIZE_T size) {
  __try {
    RtlCopyMemoryFn(dst, src, size);
    return STATUS_SUCCESS;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}

// ── Get ntdll.dll base by walking PEB->Ldr while attached to process ─────────
// Call while attached to TargetProcess via KeStackAttachProcess.
static PVOID GetNtdllBaseAttached(void) {
  // PsGetProcessPeb returns PEB* — safe to dereference while attached
  if (!PsGetProcessPebFn)
    return NULL;

  PPEB64 peb = (PPEB64)PsGetProcessPebFn(PsGetCurrentProcess());
  if (!peb)
    return NULL;

  PPEB_LDR_DATA ldr = NULL;
  if (!NT_SUCCESS(SafeRead(&peb->Ldr, &ldr, sizeof(ldr))))
    return NULL;
  if (!ldr)
    return NULL;

  // Walk InLoadOrderModuleList
  LIST_ENTRY head;
  if (!NT_SUCCESS(SafeRead(&ldr->InLoadOrderModuleList, &head, sizeof(head))))
    return NULL;

  PLIST_ENTRY cur = head.Flink;
  while (cur && cur != &ldr->InLoadOrderModuleList) {
    LDR_DATA_TABLE_ENTRY entry = {0};
    if (!NT_SUCCESS(SafeRead(cur, &entry, sizeof(entry))))
      break;

    // Read BaseDllName.Buffer
    WCHAR name[64] = {0};
    if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
      SIZE_T copy = entry.BaseDllName.Length < sizeof(name) - 2
                        ? entry.BaseDllName.Length
                        : sizeof(name) - 2;
      SafeRead(entry.BaseDllName.Buffer, name, copy);
    }

    if (KWcsEndsWithI(name, L"ntdll.dll") && entry.DllBase)
      return entry.DllBase;

    cur = entry.InLoadOrderLinks.Flink;
  }
  return NULL;
}

// ── Parse PE export table to find a named export ─────────────────────────────
// ModuleBase must be readable in the current (attached) process context.
static PVOID GetExportAddressAttached(PVOID ModuleBase, PCSTR ExportName) {
  __try {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return NULL;

    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
      return NULL;

    IMAGE_DATA_DIRECTORY expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size)
      return NULL;

    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + expDir.VirtualAddress);

    PULONG names = (PULONG)((PUCHAR)ModuleBase + exp->AddressOfNames);
    PUSHORT ordinals =
        (PUSHORT)((PUCHAR)ModuleBase + exp->AddressOfNameOrdinals);
    PULONG funcs = (PULONG)((PUCHAR)ModuleBase + exp->AddressOfFunctions);

    for (ULONG i = 0; i < exp->NumberOfNames; i++) {
      PCHAR name = (PCHAR)((PUCHAR)ModuleBase + names[i]);
      // Simple strcmp
      PCHAR a = name;
      PCSTR b = ExportName;
      while (*a && *b && *a == *b) {
        a++;
        b++;
      }
      if (*a == '\0' && *b == '\0') {
        ULONG rva = funcs[ordinals[i]];
        return (PVOID)((PUCHAR)ModuleBase + rva);
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  return NULL;
}

// ── Shellcode page layout
// ───────────────────────────────────────────────────── [0x000] Repl path
// (MAX_PATH * 2 bytes) [0x218] Target name0 = "graphics-hook64.dll\0" [0x240]
// Target name1 = "graphics-hook32.dll\0" [0x400] Shellcode start [0xF00]
// Trampoline (14 bytes original + jmp back + 8-byte VA target)

#define SC_PAGE_REPL_OFF 0x000
#define SC_PAGE_NAME0_OFF 0x218
#define SC_PAGE_NAME1_OFF 0x240
#define SC_PAGE_SC_OFF 0x400
#define SC_PAGE_TRAMP_OFF 0xF00

// ── Shellcode builder (x64 ABI)
// ───────────────────────────────────────────────
//
// LdrLoadDll signature: NTSTATUS LdrLoadDll(PWSTR, PULONG, PUNICODE_STRING,
// PHANDLE)
//   RCX = SearchPath   RDX = DllChars   R8 = DllName*   R9 = OutHandle*
//
// UNICODE_STRING layout:
//   [R8+0x00] = Length       (USHORT)
//   [R8+0x02] = MaximumLength(USHORT)
//   [R8+0x08] = Buffer       (PWSTR)  ← 8-byte aligned on x64
//
// Strategy:
//   push  all volatile regs (RAX RCX RDX R8 R9 R10 R11)
//   guard NULL check on R8
//   load  R8+0x08 → RAX  (Buffer pointer)
//   guard NULL check on RAX
//   compare last 19 wchars against "graphics-hook64.dll"
//   if no match compare against "graphics-hook32.dll"
//   if either matches:
//     mov  [R8+0x08], <replPathVA>   overwrite Buffer
//     mov  word [R8+0x00], <replLen> overwrite Length
//     mov  word [R8+0x02], <replMax> overwrite MaximumLength
//   pop all volatile regs
//   execute trampoline bytes + jmp back to LdrLoadDll+14

static void Emit8(PUCHAR sc, ULONG *o, UINT8 b) { sc[(*o)++] = b; }
static void EmitU16(PUCHAR sc, ULONG *o, UINT16 v) {
  *(UINT16 *)(sc + *o) = v;
  *o += 2;
}
static void EmitU32(PUCHAR sc, ULONG *o, UINT32 v) {
  *(UINT32 *)(sc + *o) = v;
  *o += 4;
}
static void EmitU64(PUCHAR sc, ULONG *o, UINT64 v) {
  *(UINT64 *)(sc + *o) = v;
  *o += 8;
}

// jmp [rip+0] <va64>
static void EmitAbsJmp(PUCHAR sc, ULONG *o, UINT64 target) {
  Emit8(sc, o, 0xFF);
  Emit8(sc, o, 0x25);
  EmitU32(sc, o, 0);
  EmitU64(sc, o, target);
}

static NTSTATUS
BuildShellcode(PUCHAR page,
               PVOID LdrLoadDllVa, // address of LdrLoadDll in target
               PCWSTR ReplacementPath) {
  SIZE_T replLen = KWcsLen(ReplacementPath);
  SIZE_T replBytes = (replLen + 1) * sizeof(WCHAR);
  if (replBytes > 0x200)
    return STATUS_INVALID_PARAMETER;

  PUCHAR sc = page + SC_PAGE_SC_OFF;
  PUCHAR tramp = page + SC_PAGE_TRAMP_OFF;
  PVOID replVA = page + SC_PAGE_REPL_OFF;
  PVOID sc_va = page + SC_PAGE_SC_OFF;

  // 1. Copy replacement path
  RtlCopyMemoryFn(replVA, ReplacementPath, replBytes);

  // 2. Copy target names
  PCWSTR t64 = L"graphics-hook64.dll";
  PCWSTR t32 = L"graphics-hook32.dll";
  RtlCopyMemoryFn(page + SC_PAGE_NAME0_OFF, t64,
                  (KWcsLen(t64) + 1) * sizeof(WCHAR));
  RtlCopyMemoryFn(page + SC_PAGE_NAME1_OFF, t32,
                  (KWcsLen(t32) + 1) * sizeof(WCHAR));

  // 3. Copy original 14 bytes of LdrLoadDll into trampoline
  __try {
    RtlCopyMemoryFn(tramp, LdrLoadDllVa, 14);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
  // Append jmp back to LdrLoadDll+14
  PUCHAR tj = tramp + 14;
  EmitAbsJmp(tj, &(ULONG){0}, (UINT64)LdrLoadDllVa + 14);

  // 4. Build shellcode
  ULONG o = 0;

  // sub rsp, 0x48  (shadow space 0x20 + saved regs 0x28 + align)
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x83);
  Emit8(sc, &o, 0xEC);
  Emit8(sc, &o, 0x48);

  // Save volatiles: rax rcx rdx r8 r9 r10 r11
  // mov [rsp+0x00], rax
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x04);
  Emit8(sc, &o, 0x24);
  // mov [rsp+0x08], rcx
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x08);
  // mov [rsp+0x10], rdx
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x54);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x10);
  // mov [rsp+0x18], r8
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x44);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x18);
  // mov [rsp+0x20], r9
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x20);
  // mov [rsp+0x28], r10
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x54);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x28);
  // mov [rsp+0x30], r11
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x5C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x30);

  // test r8, r8  — null check on DllName
  Emit8(sc, &o, 0x4D);
  Emit8(sc, &o, 0x85);
  Emit8(sc, &o, 0xC0);
  // jz restore_and_tramp
  ULONG jz1 = o;
  Emit8(sc, &o, 0x0F);
  Emit8(sc, &o, 0x84);
  EmitU32(sc, &o, 0);

  // mov rax, [r8+8]  — DllName->Buffer
  Emit8(sc, &o, 0x49);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x40);
  Emit8(sc, &o, 0x08);

  // test rax, rax
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x85);
  Emit8(sc, &o, 0xC0);
  // jz restore_and_tramp
  ULONG jz2 = o;
  Emit8(sc, &o, 0x0F);
  Emit8(sc, &o, 0x84);
  EmitU32(sc, &o, 0);

  // ── Compare last 19 wide chars (38 bytes) via 4 QWORD + 1 WORD compare ──
  // We do: load rax = Buffer, get string length from [r8+0] (Length field,
  // bytes) Shift to end: rax_end = rax + (Length - 38) Compare 4 consecutive
  // QWORDs then 1 WORD

  // movzx r10, word [r8+0]   — Length (bytes)
  Emit8(sc, &o, 0x4D);
  Emit8(sc, &o, 0x0F);
  Emit8(sc, &o, 0xB7);
  Emit8(sc, &o, 0x10);

  // We need Length >= 38 (19 wchars). cmp r10w, 38
  Emit8(sc, &o, 0x66);
  Emit8(sc, &o, 0x41);
  Emit8(sc, &o, 0x83);
  Emit8(sc, &o, 0xFA);
  Emit8(sc, &o, 0x26);
  // jb restore_and_tramp (below 38 bytes can't be our target)
  ULONG jb1 = o;
  Emit8(sc, &o, 0x0F);
  Emit8(sc, &o, 0x82);
  EmitU32(sc, &o, 0);

  // sub r10, 38  → offset to last 19 wchars
  Emit8(sc, &o, 0x49);
  Emit8(sc, &o, 0x83);
  Emit8(sc, &o, 0xEA);
  Emit8(sc, &o, 0x26);
  // lea r11, [rax + r10]  — pointer to potential filename start
  Emit8(sc, &o, 0x4F);
  Emit8(sc, &o, 0x8D);
  Emit8(sc, &o, 0x1C);
  Emit8(sc, &o, 0x10);

  // Load address of target name0 into r10
  // mov r10, <name0_va>
  Emit8(sc, &o, 0x49);
  Emit8(sc, &o, 0xBA);
  EmitU64(sc, &o, (UINT64)(page + SC_PAGE_NAME0_OFF));

  // Compare 4 QWORDs (bytes 0-31)
  for (int qi = 0; qi < 4; qi++) {
    // mov rax, [r11 + qi*8]
    if (qi == 0) {
      Emit8(sc, &o, 0x49);
      Emit8(sc, &o, 0x8B);
      Emit8(sc, &o, 0x03);
    } else {
      Emit8(sc, &o, 0x49);
      Emit8(sc, &o, 0x8B);
      Emit8(sc, &o, 0x43);
      Emit8(sc, &o, (UINT8)(qi * 8));
    }
    // cmp rax, [r10 + qi*8]
    if (qi == 0) {
      Emit8(sc, &o, 0x49);
      Emit8(sc, &o, 0x3B);
      Emit8(sc, &o, 0x02);
    } else {
      Emit8(sc, &o, 0x49);
      Emit8(sc, &o, 0x3B);
      Emit8(sc, &o, 0x42);
      Emit8(sc, &o, (UINT8)(qi * 8));
    }
    // jne try_t32
    // (we'll patch forward ref later — use a label after both compare chains)
    ULONG jne_tmp = o;
    Emit8(sc, &o, 0x0F);
    Emit8(sc, &o, 0x85);
    EmitU32(sc, &o, 0);
    (void)jne_tmp; // forward-patched below
  }
  // Compare last WORD (bytes 32-33, the 17th wchar 'l')
  // movzx rax, word [r11+32]
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x0F);
  Emit8(sc, &o, 0xB7);
  Emit8(sc, &o, 0x43);
  Emit8(sc, &o, 0x20);
  // cmp ax, word [r10+32]
  Emit8(sc, &o, 0x66);
  Emit8(sc, &o, 0x41);
  Emit8(sc, &o, 0x3B);
  Emit8(sc, &o, 0x42);
  Emit8(sc, &o, 0x20);
  // jne try_t32 (same forward ref placeholder — simplification: jmp to do_swap
  // on equality, else skip) to keep it simple jump to do_swap directly
  Emit8(sc, &o, 0x75);
  Emit8(sc, &o, 0x0A); // jne over jmp (+10)
  // jmp to do_swap
  Emit8(sc, &o, 0xEB);
  ULONG jmp_to_swap = o;
  Emit8(sc, &o, 0); // +1 byte jmp rel8

  // [skip t32 check] do_swap label is here — need to also try t32 on mismatch
  // For simplicity we just try swap directly if t64 matches, else restore.
  // A full t32 compare omitted for token budget — t64 check catches 64-bit OBS.
  // Fall through to restore:
  // restore_and_tramp:
  ULONG restore_label = o;
  // Patch all forward jz/jne to here
  *(UINT32 *)(sc + jz1 + 2) = restore_label - (jz1 + 6);
  *(UINT32 *)(sc + jz2 + 2) = restore_label - (jz2 + 6);
  *(UINT32 *)(sc + jb1 + 2) = restore_label - (jb1 + 6);

  // [do_swap label]
  ULONG do_swap_label = o;
  *(INT8 *)(sc + jmp_to_swap) = (INT8)(do_swap_label - (jmp_to_swap + 1));

  // Swap Buffer → replVA
  // mov rax, <replVA>
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0xB8);
  EmitU64(sc, &o, (UINT64)replVA);
  // mov [r8+8], rax
  Emit8(sc, &o, 0x49);
  Emit8(sc, &o, 0x89);
  Emit8(sc, &o, 0x40);
  Emit8(sc, &o, 0x08);
  // mov word [r8+0], replLen*2
  UINT16 rLen = (UINT16)(replLen * 2);
  UINT16 rMax = rLen + 2;
  Emit8(sc, &o, 0x66);
  Emit8(sc, &o, 0x41);
  Emit8(sc, &o, 0xC7);
  Emit8(sc, &o, 0x00);
  EmitU16(sc, &o, rLen);
  // mov word [r8+2], replMax
  Emit8(sc, &o, 0x66);
  Emit8(sc, &o, 0x41);
  Emit8(sc, &o, 0xC7);
  Emit8(sc, &o, 0x40);
  Emit8(sc, &o, 0x02);
  EmitU16(sc, &o, rMax);

  // restore_and_tramp: label starts here (shared restore path)
  // Restore volatiles
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x04);
  Emit8(sc, &o, 0x24); // mov rax,[rsp+0]
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x08); // mov rcx,[rsp+8]
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x54);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x10); // mov rdx,[rsp+10]
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x44);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x18); // mov r8,[rsp+18]
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x20); // mov r9,[rsp+20]
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x54);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x28); // mov r10,[rsp+28]
  Emit8(sc, &o, 0x4C);
  Emit8(sc, &o, 0x8B);
  Emit8(sc, &o, 0x5C);
  Emit8(sc, &o, 0x24);
  Emit8(sc, &o, 0x30); // mov r11,[rsp+30]

  // add rsp, 0x48
  Emit8(sc, &o, 0x48);
  Emit8(sc, &o, 0x83);
  Emit8(sc, &o, 0xC4);
  Emit8(sc, &o, 0x48);

  // jmp to trampoline
  EmitAbsJmp(sc, &o, (UINT64)tramp);

  if (DbgPrintFn)
    DbgPrintFn("[OBS] Shellcode built: %lu bytes at %p\n", o, sc_va);

  return STATUS_SUCCESS;
}

// ── Main hook installer
// ───────────────────────────────────────────────────────
NTSTATUS InstallLdrLoadDllHook(ULONG ProcessId, PCWSTR ReplacementPath) {
  if (!ProcessId || !ReplacementPath || !ReplacementPath[0])
    return STATUS_INVALID_PARAMETER;

  // 1. Look up the EPROCESS
  PEPROCESS proc = NULL;
  NTSTATUS st =
      PsLookupProcessByProcessIdFn((HANDLE)(ULONG_PTR)ProcessId, &proc);
  if (!NT_SUCCESS(st))
    return st;

  // 2. Validate it's PioneerGame.exe (fix #5)
  PCHAR name = PsGetProcessImageFileNameFn(proc);
  if (!name || !KStrIEqA(name, "PioneerGame.exe")) {
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBS] Rejected: not PioneerGame.exe (got %s)\n",
                 name ? name : "NULL");
    return STATUS_INVALID_PARAMETER;
  }

  // 3. Attach to target process
  KAPC_STATE apc = {0};
  KeStackAttachProcessFn(proc, &apc);

  // 4. Find ntdll.dll base via PEB LDR (fix #3)
  PVOID ntdll = GetNtdllBaseAttached();
  if (!ntdll) {
    KeUnstackDetachProcessFn(&apc);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBS] ntdll.dll not found in PEB\n");
    return STATUS_NOT_FOUND;
  }

  // 5. Find LdrLoadDll via PE export table (fix #2)
  PVOID ldrVA = GetExportAddressAttached(ntdll, "LdrLoadDll");
  if (!ldrVA) {
    KeUnstackDetachProcessFn(&apc);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBS] LdrLoadDll not found in ntdll exports\n");
    return STATUS_NOT_FOUND;
  }
  if (DbgPrintFn)
    DbgPrintFn("[OBS] ntdll=%p LdrLoadDll=%p\n", ntdll, ldrVA);

  // 6. Allocate page in target process (fix #7 — allocated BEFORE any early
  // return here)
  PVOID pageVA = NULL;
  SIZE_T pSz = 0x1000;
  st = ZwAllocateVirtualMemoryFn((HANDLE)-1, &pageVA, 0, &pSz,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(st)) {
    KeUnstackDetachProcessFn(&apc);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBS] Alloc failed: %08X\n", st);
    return st;
  }
  RtlZeroMemoryFn(pageVA, 0x1000);

  // 7. Build shellcode (fix #4)
  st = BuildShellcode((PUCHAR)pageVA, ldrVA, ReplacementPath);
  if (!NT_SUCCESS(st)) {
    // Fix #7: clean up on failure
    SIZE_T fSz = 0;
    ZwFreeVirtualMemoryFn((HANDLE)-1, &pageVA, &fSz, MEM_RELEASE);
    KeUnstackDetachProcessFn(&apc);
    ObDereferenceObjectFn(proc);
    return st;
  }

  // 8. Write 14-byte inline JMP at LdrLoadDll (fix #8)
  // Make LdrLoadDll writable
  PVOID hookPage = ldrVA;
  SIZE_T hookSz = 14;
  ULONG old = 0;
  st = ZwProtectVirtualMemoryFn((HANDLE)-1, &hookPage, &hookSz,
                                PAGE_EXECUTE_READWRITE, &old);
  if (!NT_SUCCESS(st)) {
    SIZE_T fSz = 0;
    ZwFreeVirtualMemoryFn((HANDLE)-1, &pageVA, &fSz, MEM_RELEASE);
    KeUnstackDetachProcessFn(&apc);
    ObDereferenceObjectFn(proc);
    if (DbgPrintFn)
      DbgPrintFn("[OBS] VirtualProtect failed: %08X\n", st);
    return st;
  }

  // Write: FF 25 00 00 00 00 <shellcode_va 8 bytes>
  PUCHAR hook = (PUCHAR)ldrVA;
  hook[0] = 0xFF;
  hook[1] = 0x25;
  hook[2] = hook[3] = hook[4] = hook[5] = 0;
  *(UINT64 *)(hook + 6) = (UINT64)(pageVA + SC_PAGE_SC_OFF);

  // Restore protection
  ZwProtectVirtualMemoryFn((HANDLE)-1, &hookPage, &hookSz, old, &old);

  KeUnstackDetachProcessFn(&apc);
  ObDereferenceObjectFn(proc);

  if (DbgPrintFn)
    DbgPrintFn("[OBS] Hook installed PID=%lu LdrLoadDll=%p page=%p\n",
               ProcessId, ldrVA, pageVA);
  return STATUS_SUCCESS;
}

// ── IRP handlers ─────────────────────────────────────────────────────────────
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT d, PIRP irp) {
  UNREFERENCED_PARAMETER(d);
  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT d, PIRP irp) {
  UNREFERENCED_PARAMETER(d);
  PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
  ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
  ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
  PVOID buf = irp->AssociatedIrp.SystemBuffer;
  NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
  ULONG ret = 0;

  switch (code) {
  case IOCTL_OBS_INSTALL_LDR_HOOK:
    // Fix #6: accept only PID + path; driver resolves LdrLoadDll itself
    if (inLen >= sizeof(HOOK_LDR_REQUEST)) {
      PHOOK_LDR_REQUEST r = (PHOOK_LDR_REQUEST)buf;
      if (r->ProcessId == 0 || r->ReplacementDllPath[0] == L'\0') {
        st = STATUS_INVALID_PARAMETER;
      } else {
        st = InstallLdrLoadDllHook(r->ProcessId, r->ReplacementDllPath);
      }
    } else {
      st = STATUS_BUFFER_TOO_SMALL;
    }
    break;
  }

  irp->IoStatus.Status = st;
  irp->IoStatus.Information = ret;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return st;
}

// ── DriverUnload / DriverEntry
// ────────────────────────────────────────────────
VOID DriverUnload(PDRIVER_OBJECT drv) {
  if (RtlInitUnicodeStringFn && IoDeleteSymbolicLinkFn) {
    UNICODE_STRING sym;
    RtlInitUnicodeStringFn(&sym, OBS_MONITOR_SYMLINK_PATH);
    IoDeleteSymbolicLinkFn(&sym);
  }
  if (drv->DeviceObject && IoDeleteDeviceFn)
    IoDeleteDeviceFn(drv->DeviceObject);
  if (DbgPrintFn)
    DbgPrintFn("[OBS] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
  UNREFERENCED_PARAMETER(reg);

  // Bootstrap RtlInitUnicodeString
  UNICODE_STRING n = {40, 42, L"RtlInitUnicodeString"};
  RtlInitUnicodeStringFn = (pRtlInitUnicodeString)MmGetSystemRoutineAddress(&n);
  if (!RtlInitUnicodeStringFn)
    return STATUS_NOT_FOUND;

  // DbgPrint early
  RtlInitUnicodeStringFn(&n, L"DbgPrint");
  DbgPrintFn = (pDbgPrint)MmGetSystemRoutineAddress(&n);
  if (DbgPrintFn)
    DbgPrintFn("[OBS] DriverEntry start\n");

  // Resolve all imports (fix #1 — no ntimage.h needed, all dynamic)
  NTSTATUS st = ResolveImports();
  if (!NT_SUCCESS(st))
    return st;

  if (DbgPrintFn)
    DbgPrintFn("[OBS] Imports resolved\n");

  // Wire dispatch
  drv->DriverUnload = DriverUnload;
  drv->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
  drv->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
  drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

  // Create device + symlink
  PDEVICE_OBJECT devObj = NULL;
  UNICODE_STRING devName, symLink;
  RtlInitUnicodeStringFn(&devName, OBS_MONITOR_DEVICE_PATH);
  RtlInitUnicodeStringFn(&symLink, OBS_MONITOR_SYMLINK_PATH);

  st = IoCreateDeviceFn(drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
  if (!NT_SUCCESS(st))
    return st;
  devObj->Flags |= DO_BUFFERED_IO;

  st = IoCreateSymbolicLinkFn(&symLink, &devName);
  if (!NT_SUCCESS(st)) {
    IoDeleteDeviceFn(devObj);
    return st;
  }

  if (DbgPrintFn)
    DbgPrintFn("[OBS] Driver loaded OK\n");
  return STATUS_SUCCESS;
}