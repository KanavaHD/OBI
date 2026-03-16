#pragma once
#include "obs_hijacker.h"
#include <mutex>
#include <string>
#include <vector>
#include <windows.h>


struct OBSUIState {
  char ProcessSearch[256] = "";
  char ReplacementPath[MAX_PATH] = "";
  DWORD SelectedPid = 0;
  std::wstring SelectedName;
  DWORD TargetPid = 0;
  std::wstring TargetProcessName;
};

// UI Functions
bool InitWin32UI(HWND hWnd);
void UpdateProcessList(HWND hListBox);
void HandleCommand(HWND hWnd, WPARAM wParam, LPARAM lParam);
void AddLog(const char *fmt, ...);
void CleanupUI();

// Control IDs
#define IDC_LIST_PROCESSES 1001
#define IDC_EDIT_SEARCH 1002
#define IDC_EDIT_PATH 1003
#define IDC_BTN_SET_TARGET 1004
#define IDC_BTN_HOOK 1005 // Install LdrLoadDll Hook
#define IDC_BTN_REFRESH 1007
#define IDC_BTN_BACKUP 1008
#define IDC_BTN_RESTORE 1009
#define IDC_LIST_LOGS 1010
#define IDC_STATIC_TARGET 1011
#define IDC_STATIC_HOOK_ST 1012 // Hook status label