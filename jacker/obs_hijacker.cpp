#include "obs_hijacker.h"
#include <filesystem>
#include <iostream>
#include <tlhelp32.h>
#include <vector>

namespace fs = std::filesystem;

OBSHijacker::OBSHijacker() : m_hDriver(INVALID_HANDLE_VALUE) {}

OBSHijacker::~OBSHijacker() {
  if (m_hDriver != INVALID_HANDLE_VALUE)
    CloseHandle(m_hDriver);
}

bool OBSHijacker::Initialize() {
  m_hDriver = CreateFileW(OBS_MONITOR_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (m_hDriver == INVALID_HANDLE_VALUE) {
    // Driver not loaded — that's OK, some features will be unavailable
    return false;
  }
  return true;
}

bool OBSHijacker::InstallLdrHook(DWORD processId,
                                 const std::wstring &replacementPath) {
  if (m_hDriver == INVALID_HANDLE_VALUE)
    return false;

  // Resolve LdrLoadDll address in the current process.
  // Since ntdll.dll is loaded at the same VA in every process on the same
  // system, this address is valid in the target process as well.
  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtdll)
    return false;

  PVOID ldrAddr = (PVOID)GetProcAddress(hNtdll, "LdrLoadDll");
  if (!ldrAddr)
    return false;

  HOOK_LDR_REQUEST req = {0};
  req.ProcessId = processId;
  req.LdrLoadDllAddress = ldrAddr;

  if (replacementPath.size() >= MAX_PATH)
    return false;
  wcsncpy_s(req.ReplacementDllPath, replacementPath.c_str(), MAX_PATH - 1);

  DWORD bytesReturned = 0;
  return DeviceIoControl(m_hDriver, IOCTL_OBS_INSTALL_LDR_HOOK, &req,
                         sizeof(req), NULL, 0, &bytesReturned, NULL) != FALSE;
}

bool OBSHijacker::BackupOriginals() {
  try {
    std::wstring target =
        L"C:\\ProgramData\\obs-studio-hook\\graphics-hook64.dll";
    std::wstring backup =
        L"C:\\ProgramData\\obs-studio-hook\\graphics-hook64.dll.bak";
    if (fs::exists(target) && !fs::exists(backup)) {
      fs::copy_file(target, backup);
      return true;
    }
  } catch (...) {
  }
  return false;
}

bool OBSHijacker::RestoreOriginals() {
  try {
    std::wstring target =
        L"C:\\ProgramData\\obs-studio-hook\\graphics-hook64.dll";
    std::wstring backup =
        L"C:\\ProgramData\\obs-studio-hook\\graphics-hook64.dll.bak";
    if (fs::exists(backup)) {
      fs::copy_file(backup, target, fs::copy_options::overwrite_existing);
      return true;
    }
  } catch (...) {
  }
  return false;
}

bool OBSHijacker::GetProcessStats(DWORD processId, PROCESS_STATS *stats) {
  if (m_hDriver == INVALID_HANDLE_VALUE)
    return false;
  DWORD bytesReturned = 0;
  return DeviceIoControl(m_hDriver, IOCTL_OBS_GET_PROCESS_STATS, &processId,
                         sizeof(DWORD), stats, sizeof(PROCESS_STATS),
                         &bytesReturned, NULL) != FALSE;
}

std::vector<DWORD> OBSHijacker::EnumProcessIds() {
  std::vector<DWORD> pids;
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32)) {
      do {
        pids.push_back(pe32.th32ProcessID);
      } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
  }
  return pids;
}
