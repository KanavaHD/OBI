#pragma once

#ifdef _KERNEL_MODE
#include <intrin.h>
#include <ntifs.h>

#else
#include <windows.h>
#include <winioctl.h>
#endif

// Device names
#define OBS_MONITOR_DEVICE_NAME L"\\\\.\\OBSMonitor"
#define OBS_MONITOR_DEVICE_PATH L"\\Device\\OBSMonitor"
#define OBS_MONITOR_SYMLINK_PATH L"\\DosDevices\\OBSMonitor"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// ── IOCTL codes ────────────────────────────────────────────────────────────
#define IOCTL_OBS_GET_PROCESS_STATS                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Install LdrLoadDll hook — driver resolves LdrLoadDll itself.
// Only pass PID + replacement DLL path.
#define IOCTL_OBS_INSTALL_LDR_HOOK                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── Shared structures ──────────────────────────────────────────────────────
typedef struct _PROCESS_STATS {
  ULONG ProcessId;
  ULONG CpuUsage;
  ULONG PrivateBytes;
  ULONG WorkingSet;
  WCHAR ProcessName[256];
} PROCESS_STATS, *PPROCESS_STATS;

// Sent by usermode to install a LdrLoadDll hook in the given process.
// The driver will:
//   1. Validate ProcessId is PioneerGame.exe
//   2. Find ntdll.dll in the process PEB
//   3. Parse ntdll exports to find LdrLoadDll
//   4. Allocate kernel-written shellcode page
//   5. Patch LdrLoadDll with a 14-byte JMP
typedef struct _HOOK_LDR_REQUEST {
  ULONG ProcessId;                    // Target PID (must be PioneerGame.exe)
  WCHAR ReplacementDllPath[MAX_PATH]; // Full path to your custom DLL
} HOOK_LDR_REQUEST, *PHOOK_LDR_REQUEST;
