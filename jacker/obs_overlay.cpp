#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"
#include "overlay.h"
#include <dwmapi.h>
#include <windowsx.h>


// Forward declaration for ImGui proc handler
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd,
                                                             UINT msg,
                                                             WPARAM wParam,
                                                             LPARAM lParam);

Overlay::~Overlay() { Destroy(); }

LRESULT CALLBACK Overlay::WndProc(HWND hWnd, UINT msg, WPARAM wParam,
                                  LPARAM lParam) {
  if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
    return true;

  switch (msg) {
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Stripped down UpdateClickThrough specifically for the Hijacker
void Overlay::UpdateClickThrough() {
  if (!m_hWnd)
    return;

  // For the hijacker, we always want to capture input if any window is hovered
  bool shouldCapture = false;
  POINT pt;
  if (GetCursorPos(&pt)) {
    ScreenToClient(m_hWnd, &pt);
    ImVec2 mousePos((float)pt.x, (float)pt.y);

    ImGuiContext *ctx = ImGui::GetCurrentContext();
    if (ctx) {
      for (int i = 0; i < ctx->Windows.Size; i++) {
        ImGuiWindow *win = ctx->Windows[i];
        if (win && win->Active && !win->Hidden &&
            !(win->Flags & ImGuiWindowFlags_NoMouseInputs)) {
          if (mousePos.x >= win->Pos.x && mousePos.y >= win->Pos.y &&
              mousePos.x < win->Pos.x + win->Size.x &&
              mousePos.y < win->Pos.y + win->Size.y) {
            shouldCapture = true;
            break;
          }
        }
      }
    }
  }

  LONG_PTR exStyle = GetWindowLongPtrW(m_hWnd, GWL_EXSTYLE);
  bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
  bool noActivate = (exStyle & WS_EX_NOACTIVATE) != 0;

  if (shouldCapture) {
    if (isTransparent || noActivate) {
      SetWindowLongPtrW(m_hWnd, GWL_EXSTYLE,
                        exStyle & ~(WS_EX_TRANSPARENT | WS_EX_NOACTIVATE));
    }
  } else {
    if (!isTransparent || !noActivate) {
      SetWindowLongPtrW(m_hWnd, GWL_EXSTYLE,
                        exStyle | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
    }
  }
}

bool Overlay::Create(int width, int height) {
  m_width = width;
  m_height = height;
  if (!InitWindow(width, height))
    return false;
  if (!InitD3D())
    return false;
  if (!InitImGui())
    return false;
  return true;
}

bool Overlay::InitWindow(int width, int height) {
  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.lpszClassName = L"OBSHijackerOverlay";
  RegisterClassExW(&wc);

  m_hWnd =
      CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW |
                          WS_EX_NOACTIVATE | WS_EX_TRANSPARENT,
                      wc.lpszClassName, L"OBS Hijacker", WS_POPUP, 0, 0, width,
                      height, nullptr, nullptr, wc.hInstance, nullptr);

  if (!m_hWnd)
    return false;

  SetLayeredWindowAttributes(m_hWnd, RGB(0, 0, 0), 255,
                             LWA_COLORKEY | LWA_ALPHA);

  MARGINS margins = {-1, -1, -1, -1};
  DwmExtendFrameIntoClientArea(m_hWnd, &margins);

  ShowWindow(m_hWnd, SW_SHOW);
  UpdateWindow(m_hWnd);

  return true;
}

bool Overlay::InitD3D() {
  DXGI_SWAP_CHAIN_DESC sd{};
  sd.BufferCount = 2;
  sd.BufferDesc.Width = m_width;
  sd.BufferDesc.Height = m_height;
  sd.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = m_hWnd;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  D3D_FEATURE_LEVEL featureLevel;
  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
      D3D11_SDK_VERSION, &sd, &m_pSwapChain, &m_pDevice, &featureLevel,
      &m_pContext);
  if (FAILED(hr))
    return false;

  ID3D11Texture2D *backBuffer = nullptr;
  m_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
  m_pDevice->CreateRenderTargetView(backBuffer, nullptr, &m_pRenderTarget);
  backBuffer->Release();

  return true;
}

bool Overlay::InitImGui() {
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGui_ImplWin32_Init(m_hWnd);
  ImGui_ImplDX11_Init(m_pDevice, m_pContext);
  return true;
}

bool Overlay::BeginFrame() {
  UpdateClickThrough();
  MSG msg{};
  while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
    if (msg.message == WM_QUIT) {
      m_running = false;
      return false;
    }
  }
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  ImGui::NewFrame();
  return true;
}

void Overlay::EndFrame() {
  ImGui::Render();
  const float clear[4] = {0.f, 0.f, 0.f, 0.f};
  m_pContext->OMSetRenderTargets(1, &m_pRenderTarget, nullptr);
  m_pContext->ClearRenderTargetView(m_pRenderTarget, clear);
  ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
  m_pSwapChain->Present(1, 0);
}

void Overlay::Destroy() {
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  if (m_pRenderTarget)
    m_pRenderTarget->Release();
  if (m_pSwapChain)
    m_pSwapChain->Release();
  if (m_pContext)
    m_pContext->Release();
  if (m_pDevice)
    m_pDevice->Release();
  if (m_hWnd)
    DestroyWindow(m_hWnd);
}
