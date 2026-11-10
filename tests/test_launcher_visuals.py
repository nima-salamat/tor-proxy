from __future__ import annotations

from pathlib import Path


def test_windows_launcher_uses_high_resolution_png_for_splash_art():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "launcher/src/bootstrap.cpp").read_text(encoding="utf-8")

    assert r's.root + L"\\assets\\icon.png"' in source
    assert r's.root + L"\\_internal\\assets\\icon.png"' in source
    assert "std::make_unique<Gdiplus::Bitmap>(candidatePath.c_str())" in source
    assert "graphics.DrawImage(s.logo.get(), RectF(331.0f, 85.0f, 98.0f, 98.0f))" in source
    assert "const bool logoLoaded = state.logo && state.logo->GetLastStatus() == Gdiplus::Ok;" in source
    # Keep the embedded ICO for Windows shell integration, not for the splash artwork.
    assert "wc.hIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101)," in source
    assert "Bitmap logo(s.icon);" not in source


def test_windows_launcher_uses_one_consistent_rounded_window_edge():
    repository = Path(__file__).resolve().parents[1]
    source = (repository / "launcher/src/bootstrap.cpp").read_text(encoding="utf-8")
    cmake = (repository / "launcher/CMakeLists.txt").read_text(encoding="utf-8")

    assert "constexpr float kPanelCornerRadius = 25.0f;" in source
    assert "addRoundedPath(panel, canvas, kPanelCornerRadius);" in source
    assert "2.0f * kPanelCornerRadius * s.scale" in source
    assert "CreateRoundRectRgn(" in source
    assert "DwmSetWindowAttribute" not in source
    assert "DWMWCP_ROUND" not in source
    assert "Dwmapi" not in cmake
