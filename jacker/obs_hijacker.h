#pragma once
#include "../obs/obs_shared.h"
#include <string>
#include <vector>

class OBSHijacker {
public:
  OBSHijacker();
  ~OBSHijacker();

  bool Initialize();

  // Kernel-mode LdrLoadDll hook — replaces legacy usermode injection
  bool InstallLdrHook(DWORD processId, const std::wstring &replacementPath);

  // Backup/restore OBS original DLL
  bool BackupOriginals();
  bool RestoreOriginals();

  // Stats
  bool GetProcessStats(DWORD processId, PROCESS_STATS *stats);
  std::vector<DWORD> EnumProcessIds();

private:
  HANDLE m_hDriver;
};
