/* @author vmthook - Native Windows GDI+ Visualizer for binflow. */
#include <Visualizer.hpp>
#include <windows.h>
#include <gdiplus.h>
#include <map>
#include <sstream>
#include <vector>
#include <queue>
#include <unordered_set>

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

int GetEncoderClsid(const WCHAR* Format, CLSID* PClsid)
{
    UINT Num = 0; UINT Size = 0; GetImageEncodersSize(&Num, &Size);
    if (Size == 0) return -1;
    ImageCodecInfo* PImageCodecInfo = (ImageCodecInfo*)(malloc(Size));
    if (PImageCodecInfo == nullptr) return -1;
    GetImageEncoders(Num, Size, PImageCodecInfo);
    for (UINT j = 0; j < Num; ++j) { if (wcscmp(PImageCodecInfo[j].MimeType, Format) == 0) { *PClsid = PImageCodecInfo[j].Clsid; free(PImageCodecInfo); return (int)j; } }
    free(PImageCodecInfo); return -1;
}

void DrawRoundedRect(Graphics* G, Pen* P, RectF R, float Rad)
{
    GraphicsPath Path;
    Path.AddArc(R.X, R.Y, Rad, Rad, 180, 90); Path.AddArc(R.X + R.Width - Rad, R.Y, Rad, Rad, 270, 90);
    Path.AddArc(R.X + R.Width - Rad, R.Y + R.Height - Rad, Rad, Rad, 0, 90); Path.AddArc(R.X, R.Y + R.Height - Rad, Rad, Rad, 90, 90);
    Path.CloseFigure(); G->DrawPath(P, &Path);
}

void FillRoundedRect(Graphics* G, Brush* B, RectF R, float Rad)
{
    GraphicsPath Path;
    Path.AddArc(R.X, R.Y, Rad, Rad, 180, 90); Path.AddArc(R.X + R.Width - Rad, R.Y, Rad, Rad, 270, 90);
    Path.AddArc(R.X + R.Width - Rad, R.Y + R.Height - Rad, Rad, Rad, 0, 90); Path.AddArc(R.X, R.Y + R.Height - Rad, Rad, Rad, 90, 90);
    Path.CloseFigure(); G->FillPath(B, &Path);
}

void Visualizer::GenerateFlowGraph(const std::string& FileName, const std::vector<BasicBlock>& Blocks, uint64_t EntryPoint, const std::map<uint64_t, std::string>& ImportMap, const std::vector<SecurityFinding>& Findings)
{
    if (Blocks.empty()) return;
    GdiplusStartupInput GdiStart; ULONG_PTR GdiToken; GdiplusStartup(&GdiToken, &GdiStart, nullptr);
    int Width = 3840; int Height = 2160;
    Bitmap* Bmp = new Bitmap(Width, Height); Graphics* G = Graphics::FromImage(Bmp);
    G->SetSmoothingMode(SmoothingModeAntiAlias); G->SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    G->Clear(Color(255, 6, 7, 10));

    Pen DataPen(Color(180, 0, 230, 118), 1); Pen CtrlPen(Color(180, 255, 23, 68), 1); Pen DeadPen(Color(120, 100, 100, 100), 1);
    SolidBrush TextBrush(Color(255, 240, 240, 255)); SolidBrush StubBrush(Color(255, 255, 235, 59)); SolidBrush BgBrush(Color(255, 18, 20, 26)); SolidBrush RedBrush(Color(255, 255, 50, 50)); SolidBrush BlueBrush(Color(255, 80, 150, 255));
    Font LibFont(L"Consolas", 8); Font LabFont(L"Consolas", 10, FontStyleBold); Font TagFont(L"Consolas", 7, FontStyleBold);
    StringFormat StrFormat; StrFormat.SetAlignment(StringAlignmentCenter); StrFormat.SetLineAlignment(StringAlignmentCenter);

    std::map<uint64_t, const BasicBlock*> BlockMap; for (const auto& B : Blocks) BlockMap[B.Start] = &B;
    uint64_t StartAddr = (EntryPoint != 0) ? EntryPoint : Blocks[0].Start;
    std::map<int, std::vector<uint64_t>> Levels; std::unordered_set<uint64_t> Visited;
    std::queue<std::pair<uint64_t, int>> Q; Q.push({ StartAddr, 0 }); Visited.insert(StartAddr);

    while (!Q.empty() && Visited.size() < 1200)
    {
        auto [Addr, Level] = Q.front(); Q.pop(); Levels[Level].push_back(Addr);
        if (BlockMap.count(Addr) && Level < 22)
            for (uint64_t Succ : BlockMap[Addr]->Successors) if (Visited.find(Succ) == Visited.end()) { Visited.insert(Succ); Q.push({ Succ, Level + 1 }); }
    }

    float HSpace = 340.0f; float VSpace = 180.0f;
    std::map<uint64_t, PointF> Positions;
    for (auto const& [L, Nodes] : Levels)
    {
        float RowWidth = (float)(Nodes.size() - 1) * HSpace; float StartX = (Width / 2.0f) - (RowWidth / 2.0f);
        for (size_t i = 0; i < Nodes.size(); ++i) Positions[Nodes[i]] = PointF(StartX + (float)i * HSpace, 120.0f + L * VSpace);
    }

    AdjustableArrowCap ArrowCap(4, 4); Pen NormalEdge(Color(180, 255, 255, 255), 1); NormalEdge.SetCustomEndCap(&ArrowCap);
    for (auto const& [Addr, Pos] : Positions)
        if (BlockMap.count(Addr)) for (uint64_t Succ : BlockMap[Addr]->Successors) if (Positions.count(Succ)) { PointF To = Positions[Succ]; G->DrawLine(&NormalEdge, Pos.X, Pos.Y + 36, To.X, To.Y - 36); }

    for (auto const& [Addr, Pos] : Positions)
    {
        RectF Rect(Pos.X - 120, Pos.Y - 40, 240, 80); FillRoundedRect(G, &BgBrush, Rect, 14.0f);
        bool IsSec = false; std::string SecMsg = "";
        for (const auto& F : Findings) if (F.Address >= Addr && F.Address < (BlockMap.count(Addr) ? BlockMap[Addr]->End : Addr + 4)) { IsSec = true; SecMsg = F.Type; break; }

        Pen* TargetPen = &DataPen;
        if (!BlockMap.count(Addr)) TargetPen = &CtrlPen;
        else if (IsSec) TargetPen = &CtrlPen;
        else if (!BlockMap[Addr]->IsReachable) TargetPen = &DeadPen;
        else if (BlockMap[Addr]->Category == "CONTROL_FLOW") TargetPen = &CtrlPen;
        DrawRoundedRect(G, TargetPen, Rect, 14.0f);
        
        RectF TextRect(Rect.X + 10, Rect.Y + 10, Rect.Width - 20, Rect.Height - 30);
        if (BlockMap.count(Addr))
        {
            if (!BlockMap[Addr]->CustomLabel.empty()) G->DrawString(std::wstring(BlockMap[Addr]->CustomLabel.begin(), BlockMap[Addr]->CustomLabel.end()).c_str(), -1, &LabFont, PointF(Rect.X + 5, Rect.Y - 20), &BlueBrush);
            if (IsSec) G->DrawString(std::wstring(SecMsg.begin(), SecMsg.end()).c_str(), -1, &LabFont, PointF(Rect.X + 5, Rect.Y + Rect.Height + 5), &RedBrush);
            
            std::wstringstream Wss; Wss << L"0x" << std::hex << Addr << L"\n" << std::wstring(BlockMap[Addr]->Summary.begin(), BlockMap[Addr]->Summary.end());
            G->DrawString(Wss.str().c_str(), -1, &LibFont, TextRect, &StrFormat, &TextBrush);

            if (!BlockMap[Addr]->Tags.empty()) {
                std::wstring TagStr; for (const auto& T : BlockMap[Addr]->Tags) TagStr += std::wstring(T.begin(), T.end()) + L" ";
                G->DrawString(TagStr.c_str(), -1, &TagFont, PointF(Rect.X + 5, Rect.Y + Rect.Height - 15), &StubBrush);
            }
        }
    }
    CLSID PngClsid; std::wstring WFileName(FileName.begin(), FileName.end());
    if (GetEncoderClsid(L"image/png", &PngClsid) != -1) Bmp->Save(WFileName.c_str(), &PngClsid, nullptr);
    delete G; delete Bmp; GdiplusShutdown(GdiToken);
}
