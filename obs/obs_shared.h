#pragma once

#ifdef _KERNEL_MODE
#include <intrin.h>
#include <ntifs.h>

#else
#include <windows.h>
#include <winioctl.h>
#endif

// Device Name
#define OBS_MONITOR_DEVICE_NAME L"\\\\.\\OBSMonitor"
#define OBS_MONITOR_DEVICE_PATH L"\\Device\\OBSMonitor"
#define OBS_MONITOR_SYMLINK_PATH L"\\DosDevices\\OBSMonitor"

typedef struct _PROCESS_STATS {
  ULONG ProcessId;
  ULONG CpuUsage;
  ULONG PrivateBytes;
  ULONG WorkingSet;
  WCHAR ProcessName[256];
} PROCESS_STATS, *PPROCESS_STATS;

// IOCTL Codes
#define IOCTL_OBS_SET_TARGET_DLL                                               \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBS_GET_INJECTION_STATUS                                         \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBS_TOGGLE_MONITORING                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBS_GET_PROCESS_STATS                                            \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// New IOCTL: install LdrLoadDll hook in target process
#define IOCTL_OBS_INSTALL_LDR_HOOK                                             \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Shared Structures
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

typedef struct _OBS_TARGET_CONFIG {
  WCHAR TargetDllPath
      [MAX_PATH]; // "C:\ProgramData\obs-studio-hook\graphics-hook64.dll"
  WCHAR ReplacementDllPath[MAX_PATH]; // "C:\ARD\custom-hook.dll"
  INT Active;
} OBS_TARGET_CONFIG, *POBS_TARGET_CONFIG;

// Request structure for LdrLoadDll hook installation
typedef struct _HOOK_LDR_REQUEST {
  ULONG ProcessId;
  PVOID LdrLoadDllAddress;            // ntdll!LdrLoadDll in target process
  WCHAR ReplacementDllPath[MAX_PATH]; // your custom DLL full path
} HOOK_LDR_REQUEST, *PHOOK_LDR_REQUEST;
