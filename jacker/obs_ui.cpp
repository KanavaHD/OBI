#include "obs_ui.h"
#include <commctrl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "comctl32.lib")

OBSUIState g_OBSUIState;
extern OBSHijacker g_Hijacker;

HWND g_hListBoxProcesses = NULL;
HWND g_hListBoxLogs = NULL;
HWND g_hStaticTarget = NULL;
HWND g_hStaticHookSt = NULL;
HWND g_hBtnHook = NULL;

// ─── Log ────────────────────────────────────────────────────────────────────
void AddLog(const char *fmt, ...) {
  char buf[1024];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  if (g_hListBoxLogs) {
    int idx = (int)SendMessageA(g_hListBoxLogs, LB_ADDSTRING, 0, (LPARAM)buf);
    SendMessage(g_hListBoxLogs, LB_SETCURSEL, idx, 0);
  }
}

// ─── Process list ───────────────────────────────────────────────────────────
void UpdateProcessList(HWND hListBox) {
  SendMessage(hListBox, LB_RESETCONTENT, 0, 0);

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(hSnap, &pe)) {
    do {
      // Apply search filter
      if (g_OBSUIState.ProcessSearch[0] != '\0') {
        char nameA[256];
        WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameA, sizeof(nameA),
                            NULL, NULL);
        // Case-insensitive search
        char hayA[256], needA[256];
        int i = 0;
        for (i = 0; nameA[i]; i++)
          hayA[i] = (char)tolower((unsigned char)nameA[i]);
        hayA[i] = 0;
        for (i = 0; g_OBSUIState.ProcessSearch[i]; i++)
          needA[i] =
              (char)tolower((unsigned char)g_OBSUIState.ProcessSearch[i]);
        needA[i] = 0;
        if (!strstr(hayA, needA))
          continue;
      }

      wchar_t entry[512];
      swprintf(entry, 512, L"[%lu]  %s", pe.th32ProcessID, pe.szExeFile);
      int idx = (int)SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)entry);
      SendMessage(hListBox, LB_SETITEMDATA, idx, (LPARAM)pe.th32ProcessID);
    } while (Process32NextW(hSnap, &pe));
  }
  CloseHandle(hSnap);
}

// ─── Init UI ────────────────────────────────────────────────────────────────
bool InitWin32UI(HWND hWnd) {
  // Row 0: process filter
  CreateWindowA("STATIC", "Filter:", WS_VISIBLE | WS_CHILD, 10, 10, 60, 20,
                hWnd, NULL, NULL, NULL);
  CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                72, 10, 250, 20, hWnd, (HMENU)IDC_EDIT_SEARCH, NULL, NULL);
  CreateWindowA("BUTTON", "Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 330,
                10, 70, 20, hWnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);

  // Row 1: DLL path
  CreateWindowA("STATIC", "DLL Path:", WS_VISIBLE | WS_CHILD, 10, 40, 60, 20,
                hWnd, NULL, NULL, NULL);
  CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                72, 40, 600, 20, hWnd, (HMENU)IDC_EDIT_PATH, NULL, NULL);

  // Row 2: Target / Hook buttons
  CreateWindowA("BUTTON", "Set Target", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                10, 70, 100, 26, hWnd, (HMENU)IDC_BTN_SET_TARGET, NULL, NULL);
  g_hBtnHook = CreateWindowA("BUTTON", "Install Hook",
                             WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 120, 70,
                             110, 26, hWnd, (HMENU)IDC_BTN_HOOK, NULL, NULL);
  CreateWindowA("BUTTON", "Backup OBS", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                240, 70, 100, 26, hWnd, (HMENU)IDC_BTN_BACKUP, NULL, NULL);
  CreateWindowA("BUTTON", "Restore OBS", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                350, 70, 100, 26, hWnd, (HMENU)IDC_BTN_RESTORE, NULL, NULL);

  // Status labels
  g_hStaticTarget =
      CreateWindowA("STATIC", "Target: None", WS_VISIBLE | WS_CHILD, 10, 105,
                    680, 18, hWnd, (HMENU)IDC_STATIC_TARGET, NULL, NULL);
  g_hStaticHookSt =
      CreateWindowA("STATIC", "Hook: Not installed", WS_VISIBLE | WS_CHILD, 10,
                    123, 680, 18, hWnd, (HMENU)IDC_STATIC_HOOK_ST, NULL, NULL);

  // Process list
  g_hListBoxProcesses = CreateWindowA(
      "LISTBOX", NULL,
      WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY, 10, 148, 680,
      290, hWnd, (HMENU)IDC_LIST_PROCESSES, NULL, NULL);

  // Log window
  g_hListBoxLogs = CreateWindowA(
      "LISTBOX", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL, 10, 448,
      780, 150, hWnd, (HMENU)IDC_LIST_LOGS, NULL, NULL);

  // Init hijacker (optional — may fail if driver not loaded)
  if (!g_Hijacker.Initialize())
    AddLog("[!] Driver not found — hook will fail. Load the driver first.");
  else
    AddLog("[*] Driver connected OK.");

  UpdateProcessList(g_hListBoxProcesses);
  AddLog("[*] UI ready.");
  return true;
}

// ─── Command handler ─────────────────────────────────────────────────────────
void HandleCommand(HWND hWnd, WPARAM wParam, LPARAM lParam) {
  int wmId = LOWORD(wParam);
  int wmEvent = HIWORD(wParam);

  switch (wmId) {

  case IDC_EDIT_SEARCH:
    if (wmEvent == EN_CHANGE) {
      GetWindowTextA((HWND)lParam, g_OBSUIState.ProcessSearch, 256);
      UpdateProcessList(g_hListBoxProcesses);
    }
    break;

  case IDC_EDIT_PATH:
    if (wmEvent == EN_CHANGE)
      GetWindowTextA((HWND)lParam, g_OBSUIState.ReplacementPath, MAX_PATH);
    break;

  case IDC_LIST_PROCESSES:
    if (wmEvent == LBN_SELCHANGE) {
      int idx = (int)SendMessage(g_hListBoxProcesses, LB_GETCURSEL, 0, 0);
      if (idx != LB_ERR) {
        g_OBSUIState.SelectedPid =
            (DWORD)SendMessage(g_hListBoxProcesses, LB_GETITEMDATA, idx, 0);
        wchar_t buf[512];
        SendMessageW(g_hListBoxProcesses, LB_GETTEXT, idx, (LPARAM)buf);
        g_OBSUIState.SelectedName = buf;
      }
    }
    break;

  case IDC_BTN_REFRESH:
    UpdateProcessList(g_hListBoxProcesses);
    AddLog("[*] List refreshed.");
    break;

  case IDC_BTN_SET_TARGET:
    if (g_OBSUIState.SelectedPid != 0) {
      g_OBSUIState.TargetPid = g_OBSUIState.SelectedPid;
      g_OBSUIState.TargetProcessName = g_OBSUIState.SelectedName;
      char lbl[512];
      snprintf(lbl, sizeof(lbl), "Target: PID %lu  |  %ws",
               g_OBSUIState.TargetPid, g_OBSUIState.TargetProcessName.c_str());
      SetWindowTextA(g_hStaticTarget, lbl);
      SetWindowTextA(g_hStaticHookSt, "Hook: Not installed");
      AddLog("[+] Target set: PID %lu", g_OBSUIState.TargetPid);
    } else {
      AddLog("[-] Select a process first.");
    }
    break;

  case IDC_BTN_HOOK: {
    if (g_OBSUIState.TargetPid == 0) {
      AddLog("[-] Set a target process first.");
      break;
    }
    if (g_OBSUIState.ReplacementPath[0] == '\0') {
      AddLog("[-] Enter a replacement DLL path first.");
      break;
    }
    std::wstring wpath(g_OBSUIState.ReplacementPath,
                       g_OBSUIState.ReplacementPath +
                           strlen(g_OBSUIState.ReplacementPath));
    AddLog("[*] Installing LdrLoadDll hook in PID %lu ...",
           g_OBSUIState.TargetPid);
    if (g_Hijacker.InstallLdrHook(g_OBSUIState.TargetPid, wpath)) {
      SetWindowTextA(g_hStaticHookSt, "Hook: INSTALLED (LdrLoadDll)");
      AddLog("[+] Hook installed — next load of graphics-hook*.dll will be "
             "redirected.");
    } else {
      SetWindowTextA(g_hStaticHookSt, "Hook: FAILED");
      AddLog("[-] Hook installation failed (driver loaded? run as admin?).");
    }
    break;
  }

  case IDC_BTN_BACKUP:
    if (g_Hijacker.BackupOriginals())
      AddLog("[+] OBS hook backed up.");
    else
      AddLog("[-] Backup failed (file not found or backup already exists).");
    break;

  case IDC_BTN_RESTORE:
    if (g_Hijacker.RestoreOriginals())
      AddLog("[+] OBS hook restored.");
    else
      AddLog("[-] Restore failed (no backup found).");
    break;
  }
}

void CleanupUI() {}