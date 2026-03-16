#include "obs_hijacker.h"
#include "obs_ui.h"
#include <commctrl.h>
#include <windows.h>

#pragma comment(lib, "comctl32.lib")

// Global hijacker — used by obs_ui.cpp via extern
OBSHijacker g_Hijacker;

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
  case WM_COMMAND:
    HandleCommand(hWnd, wParam, lParam);
    break;
  case WM_DESTROY:
    CleanupUI();
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcA(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdCmdLine, int nShowCmd) {
  // Initialize Common Controls
  INITCOMMONCONTROLSEX icex;
  icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
  icex.dwICC = ICC_WIN95_CLASSES;
  InitCommonControlsEx(&icex);

  WNDCLASSEXA wc = {0};
  wc.cbSize = sizeof(WNDCLASSEXA);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInstance;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = "OBSHijackerWin32";
  RegisterClassExA(&wc);

  HWND hWnd = CreateWindowExA(
      0, wc.lpszClassName, "OBS Hijacker - Native Edition",
      WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT,
      CW_USEDEFAULT, 815, 610, NULL, NULL, hInstance, NULL);

  if (!hWnd) {
    MessageBoxA(NULL, "CreateWindowExA failed.", "Fatal Error", MB_ICONERROR);
    return 0;
  }

  if (!InitWin32UI(hWnd)) {
    MessageBoxA(NULL, "UI Initialization Failed", "Error", MB_ICONERROR);
    return 0;
  }

  ShowWindow(hWnd, nShowCmd);
  UpdateWindow(hWnd);

  MSG msg = {0};
  while (GetMessageA(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageA(&msg);
  }

  return (int)msg.wParam;
}
