param(
    [int]$SegmentSeconds = 5,
    [int]$NumSegments    = 0
)

$OutputDir = "$env:USERPROFILE\Downloads\t1125_mf_video"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if ($NumSegments -eq 0) {
    Write-Host "[T1125][MF Video] Recording ${SegmentSeconds}s segments indefinitely (Ctrl+C to stop) to $OutputDir" -ForegroundColor Cyan
} else {
    Write-Host "[T1125][MF Video] Recording $NumSegments x ${SegmentSeconds}s segments to $OutputDir" -ForegroundColor Cyan
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class MFVideo
{
    static readonly Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE        = new Guid("C60AC5FE-252A-478F-A0EF-BC8FA5F7CAD3");
    static readonly Guid MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP = new Guid("8AC3587A-4AE7-42D8-99E0-0A6013EEF90F");
    static readonly Guid MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME      = new Guid("60D0E559-52F8-4FA2-BBCE-ACDB34A8EC01");
    static readonly Guid MF_MT_FRAME_SIZE                          = new Guid("1652C33D-D6B2-4012-B834-72030849A37D");
    static readonly Guid MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING  = new Guid("FB394F3D-CCF1-42EE-BBB3-F9B845D5681D");
    static readonly Guid IID_IMFMediaSource                        = new Guid("279A808D-AEC7-40C8-9C6B-A6B492C78A66");

    [DllImport("mfplat.dll",      ExactSpelling=true)] static extern int MFStartup(int version, int dwFlags);
    [DllImport("mfplat.dll",      ExactSpelling=true)] static extern int MFShutdown();
    [DllImport("mfplat.dll",      ExactSpelling=true)] static extern int MFCreateAttributes(out IMFAttributes ppAttrs, uint cInit);
    [DllImport("mf.dll",          ExactSpelling=true)] static extern int MFEnumDeviceSources(IMFAttributes pAttrs, out IntPtr ppDevices, out uint pCount);
    [DllImport("mfreadwrite.dll", ExactSpelling=true)] static extern int MFCreateSourceReaderFromMediaSource(IntPtr pSource, IMFAttributes pAttrs, out IMFSourceReader ppReader);

    [ComImport, Guid("2CD2D921-C447-44A7-A13C-4ADABFC247E3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFAttributes {
        void GetItem([In] ref Guid guidKey, IntPtr pValue);
        void GetItemType([In] ref Guid guidKey, out int pType);
        void CompareItem([In] ref Guid guidKey, IntPtr Value, out bool pbResult);
        void Compare(IMFAttributes pTheirs, int MatchType, out bool pbResult);
        void GetUINT32([In] ref Guid guidKey, out int punValue);
        void GetUINT64([In] ref Guid guidKey, out long punValue);
        void GetDouble([In] ref Guid guidKey, out double pfValue);
        void GetGUID([In] ref Guid guidKey, out Guid pguidValue);
        void GetStringLength([In] ref Guid guidKey, out int pcchLength);
        void GetString([In] ref Guid guidKey, [Out, MarshalAs(UnmanagedType.LPWStr)] out string pwszValue, int cchBufSize, IntPtr pcchLength);
        void GetAllocatedString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] out string ppwszValue, out int pcchLength);
        void GetBlobSize([In] ref Guid guidKey, out int pcbBlobSize);
        void GetBlob([In] ref Guid guidKey, [Out] byte[] pBuf, int cbBufSize, IntPtr pcbBlobSize);
        void GetAllocatedBlob([In] ref Guid guidKey, out IntPtr ppBuf, out int pcbSize);
        void GetUnknown([In] ref Guid guidKey, [In] ref Guid riid, out IntPtr ppv);
        void SetItem([In] ref Guid guidKey, IntPtr Value);
        void DeleteItem([In] ref Guid guidKey);
        void DeleteAllItems();
        void SetUINT32([In] ref Guid guidKey, int unValue);
        void SetUINT64([In] ref Guid guidKey, long unValue);
        void SetDouble([In] ref Guid guidKey, double fValue);
        void SetGUID([In] ref Guid guidKey, [In] ref Guid guidValue);
        void SetString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] string wszValue);
        void SetBlob([In] ref Guid guidKey, [In] byte[] pBuf, int cbBufSize);
        void SetUnknown([In] ref Guid guidKey, [MarshalAs(UnmanagedType.IUnknown)] object pUnknown);
        void LockStore();
        void UnlockStore();
        void GetCount(out int pcItems);
        void GetItemByIndex(int unIndex, out Guid pguidKey, IntPtr pValue);
        void CopyAllItems(IMFAttributes pDest);
    }

    [ComImport, Guid("7FEE9E9A-4A89-47A6-899C-B6A53A70FB67"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFActivate {
        void GetItem([In] ref Guid guidKey, IntPtr pValue);
        void GetItemType([In] ref Guid guidKey, out int pType);
        void CompareItem([In] ref Guid guidKey, IntPtr Value, out bool pbResult);
        void Compare(IMFAttributes pTheirs, int MatchType, out bool pbResult);
        void GetUINT32([In] ref Guid guidKey, out int punValue);
        void GetUINT64([In] ref Guid guidKey, out long punValue);
        void GetDouble([In] ref Guid guidKey, out double pfValue);
        void GetGUID([In] ref Guid guidKey, out Guid pguidValue);
        void GetStringLength([In] ref Guid guidKey, out int pcchLength);
        void GetString([In] ref Guid guidKey, [Out, MarshalAs(UnmanagedType.LPWStr)] out string pwszValue, int cchBufSize, IntPtr pcchLength);
        void GetAllocatedString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] out string ppwszValue, out int pcchLength);
        void GetBlobSize([In] ref Guid guidKey, out int pcbBlobSize);
        void GetBlob([In] ref Guid guidKey, [Out] byte[] pBuf, int cbBufSize, IntPtr pcbBlobSize);
        void GetAllocatedBlob([In] ref Guid guidKey, out IntPtr ppBuf, out int pcbSize);
        void GetUnknown([In] ref Guid guidKey, [In] ref Guid riid, out IntPtr ppv);
        void SetItem([In] ref Guid guidKey, IntPtr Value);
        void DeleteItem([In] ref Guid guidKey);
        void DeleteAllItems();
        void SetUINT32([In] ref Guid guidKey, int unValue);
        void SetUINT64([In] ref Guid guidKey, long unValue);
        void SetDouble([In] ref Guid guidKey, double fValue);
        void SetGUID([In] ref Guid guidKey, [In] ref Guid guidValue);
        void SetString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] string wszValue);
        void SetBlob([In] ref Guid guidKey, [In] byte[] pBuf, int cbBufSize);
        void SetUnknown([In] ref Guid guidKey, [MarshalAs(UnmanagedType.IUnknown)] object pUnknown);
        void LockStore();
        void UnlockStore();
        void GetCount(out int pcItems);
        void GetItemByIndex(int unIndex, out Guid pguidKey, IntPtr pValue);
        void CopyAllItems(IMFAttributes pDest);
        [PreserveSig] int ActivateObject([In] ref Guid riid, out IntPtr ppv);
        [PreserveSig] int ShutdownObject();
        [PreserveSig] int DetachObject();
    }

    [ComImport, Guid("44AE0FA8-EA31-4109-8D2E-4CAE4997C555"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFMediaType {
        void GetItem([In] ref Guid guidKey, IntPtr pValue);
        void GetItemType([In] ref Guid guidKey, out int pType);
        void CompareItem([In] ref Guid guidKey, IntPtr Value, out bool pbResult);
        void Compare(IMFAttributes pTheirs, int MatchType, out bool pbResult);
        void GetUINT32([In] ref Guid guidKey, out int punValue);
        void GetUINT64([In] ref Guid guidKey, out long punValue);
        void GetDouble([In] ref Guid guidKey, out double pfValue);
        void GetGUID([In] ref Guid guidKey, out Guid pguidValue);
        void GetStringLength([In] ref Guid guidKey, out int pcchLength);
        void GetString([In] ref Guid guidKey, [Out, MarshalAs(UnmanagedType.LPWStr)] out string pwszValue, int cchBufSize, IntPtr pcchLength);
        void GetAllocatedString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] out string ppwszValue, out int pcchLength);
        void GetBlobSize([In] ref Guid guidKey, out int pcbBlobSize);
        void GetBlob([In] ref Guid guidKey, [Out] byte[] pBuf, int cbBufSize, IntPtr pcbBlobSize);
        void GetAllocatedBlob([In] ref Guid guidKey, out IntPtr ppBuf, out int pcbSize);
        void GetUnknown([In] ref Guid guidKey, [In] ref Guid riid, out IntPtr ppv);
        void SetItem([In] ref Guid guidKey, IntPtr Value);
        void DeleteItem([In] ref Guid guidKey);
        void DeleteAllItems();
        void SetUINT32([In] ref Guid guidKey, int unValue);
        void SetUINT64([In] ref Guid guidKey, long unValue);
        void SetDouble([In] ref Guid guidKey, double fValue);
        void SetGUID([In] ref Guid guidKey, [In] ref Guid guidValue);
        void SetString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] string wszValue);
        void SetBlob([In] ref Guid guidKey, [In] byte[] pBuf, int cbBufSize);
        void SetUnknown([In] ref Guid guidKey, [MarshalAs(UnmanagedType.IUnknown)] object pUnknown);
        void LockStore();
        void UnlockStore();
        void GetCount(out int pcItems);
        void GetItemByIndex(int unIndex, out Guid pguidKey, IntPtr pValue);
        void CopyAllItems(IMFAttributes pDest);
        void GetMajorType(out Guid pguidMajorType);
        void IsCompressedFormat(out bool pfCompressed);
        void IsEqual(IMFMediaType pIMediaType, out int pdwFlags);
        void GetRepresentation([In] Guid guidRepresentation, out IntPtr ppvRepresentation);
        void FreeRepresentation([In] Guid guidRepresentation, IntPtr pvRepresentation);
    }

    [ComImport, Guid("70AE66F2-C809-4E4F-8915-BDCB406B7993"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFSourceReader {
        [PreserveSig] int GetStreamSelection(int dwStreamIndex, out bool pfSelected);
        [PreserveSig] int SetStreamSelection(int dwStreamIndex, bool fSelected);
        [PreserveSig] int GetNativeMediaType(int dwStreamIndex, int dwMediaTypeIndex, out IMFMediaType ppMediaType);
        [PreserveSig] int GetCurrentMediaType(int dwStreamIndex, out IMFMediaType ppMediaType);
        [PreserveSig] int SetCurrentMediaType(int dwStreamIndex, IntPtr pdwReserved, IMFMediaType pMediaType);
        [PreserveSig] int SetCurrentPosition([In] ref Guid guidTimeFormat, IntPtr varPosition);
        [PreserveSig] int ReadSample(int dwStreamIndex, int dwControlFlags, out int pdwActualStreamIndex, out int pdwStreamFlags, out long pllTimestamp, out IMFSample ppSample);
        [PreserveSig] int Flush(int dwStreamIndex);
        [PreserveSig] int GetServiceForStream(int dwStreamIndex, [In] ref Guid guidService, [In] ref Guid riid, out IntPtr ppvObject);
        [PreserveSig] int GetPresentationAttribute(int dwStreamIndex, [In] ref Guid guidAttribute, IntPtr pvarAttribute);
    }

    [ComImport, Guid("C40A00F2-B93A-4D80-AE8C-5A1C634F58E4"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFSample {
        void GetItem([In] ref Guid guidKey, IntPtr pValue);
        void GetItemType([In] ref Guid guidKey, out int pType);
        void CompareItem([In] ref Guid guidKey, IntPtr Value, out bool pbResult);
        void Compare(IMFAttributes pTheirs, int MatchType, out bool pbResult);
        void GetUINT32([In] ref Guid guidKey, out int punValue);
        void GetUINT64([In] ref Guid guidKey, out long punValue);
        void GetDouble([In] ref Guid guidKey, out double pfValue);
        void GetGUID([In] ref Guid guidKey, out Guid pguidValue);
        void GetStringLength([In] ref Guid guidKey, out int pcchLength);
        void GetString([In] ref Guid guidKey, [Out, MarshalAs(UnmanagedType.LPWStr)] out string pwszValue, int cchBufSize, IntPtr pcchLength);
        void GetAllocatedString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] out string ppwszValue, out int pcchLength);
        void GetBlobSize([In] ref Guid guidKey, out int pcbBlobSize);
        void GetBlob([In] ref Guid guidKey, [Out] byte[] pBuf, int cbBufSize, IntPtr pcbBlobSize);
        void GetAllocatedBlob([In] ref Guid guidKey, out IntPtr ppBuf, out int pcbSize);
        void GetUnknown([In] ref Guid guidKey, [In] ref Guid riid, out IntPtr ppv);
        void SetItem([In] ref Guid guidKey, IntPtr Value);
        void DeleteItem([In] ref Guid guidKey);
        void DeleteAllItems();
        void SetUINT32([In] ref Guid guidKey, int unValue);
        void SetUINT64([In] ref Guid guidKey, long unValue);
        void SetDouble([In] ref Guid guidKey, double fValue);
        void SetGUID([In] ref Guid guidKey, [In] ref Guid guidValue);
        void SetString([In] ref Guid guidKey, [MarshalAs(UnmanagedType.LPWStr)] string wszValue);
        void SetBlob([In] ref Guid guidKey, [In] byte[] pBuf, int cbBufSize);
        void SetUnknown([In] ref Guid guidKey, [MarshalAs(UnmanagedType.IUnknown)] object pUnknown);
        void LockStore();
        void UnlockStore();
        void GetCount(out int pcItems);
        void GetItemByIndex(int unIndex, out Guid pguidKey, IntPtr pValue);
        void CopyAllItems(IMFAttributes pDest);
        void GetSampleFlags(out int pdwSampleFlags);
        void SetSampleFlags(int dwSampleFlags);
        void GetSampleTime(out long phnsSampleTime);
        void SetSampleTime(long hnsSampleTime);
        void GetSampleDuration(out long phnsSampleDuration);
        void SetSampleDuration(long hnsSampleDuration);
        void GetBufferCount(out int pdwBufferCount);
        [PreserveSig] int GetBufferByIndex(int dwIndex, out IMFMediaBuffer ppBuffer);
        [PreserveSig] int ConvertToContiguousBuffer(out IMFMediaBuffer ppBuffer);
        void AddBuffer(IMFMediaBuffer pBuffer);
        void RemoveBufferByIndex(int dwIndex);
        void RemoveAllBuffers();
        void GetTotalLength(out int pcbTotalLength);
        void CopyToBuffer(IMFMediaBuffer pBuffer);
    }

    [ComImport, Guid("045FA593-8799-42B8-BC8D-8968C6453507"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMFMediaBuffer {
        [PreserveSig] int Lock(out IntPtr ppbBuffer, out int pcbMaxLength, out int pcbCurrentLength);
        [PreserveSig] int Unlock();
        [PreserveSig] int GetCurrentLength(out int pcbCurrentLength);
        [PreserveSig] int SetCurrentLength(int cbCurrentLength);
        [PreserveSig] int GetMaxLength(out int pcbMaxLength);
    }

    public static volatile bool StopRequested = false;

    public static string RecordSegments(string outputDir, int segmentSecs, int numSegments)
    {
        const int MF_VERSION  = 0x00020070;
        const int FIRST_VIDEO = unchecked((int)0xFFFFFFFC);
        const long HNS_PER_SEC = 10000000L;
        const int OUT_FPS  = 10;
        const int OUT_W    = 640;
        const int OUT_H    = 360;

        int hr = MFStartup(MF_VERSION, 0);
        if (hr < 0) return string.Format("MFStartup failed: 0x{0:X8}", hr);

        try
        {
            IMFAttributes da; MFCreateAttributes(out da, 1);
            Guid sk = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE;
            Guid sv = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP;
            da.SetGUID(ref sk, ref sv);
            IntPtr ppd; uint cnt;
            hr = MFEnumDeviceSources(da, out ppd, out cnt);
            Marshal.ReleaseComObject(da);
            if (hr < 0 || cnt == 0) return "No cameras found";

            IntPtr ap = Marshal.ReadIntPtr(ppd, 0);
            IMFActivate act = (IMFActivate)Marshal.GetObjectForIUnknown(ap);
            string camName = ""; int nl = 0;
            Guid fnk = MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME;
            try { act.GetAllocatedString(ref fnk, out camName, out nl); } catch {}

            IntPtr ps; Guid iid = IID_IMFMediaSource;
            hr = act.ActivateObject(ref iid, out ps);
            if (hr < 0) { Marshal.ReleaseComObject(act); return string.Format("ActivateObject failed: 0x{0:X8}", hr); }

            IMFAttributes ra; MFCreateAttributes(out ra, 1);
            Guid vpk = MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING;
            ra.SetUINT32(ref vpk, 1);
            IMFSourceReader reader;
            hr = MFCreateSourceReaderFromMediaSource(ps, ra, out reader);
            Marshal.ReleaseComObject(ra);
            if (hr < 0) { Marshal.Release(ps); Marshal.ReleaseComObject(act); return string.Format("CreateSourceReader failed: 0x{0:X8}", hr); }

            int srcW = 1920, srcH = 1080;
            IMFMediaType nmt;
            if (reader.GetCurrentMediaType(FIRST_VIDEO, out nmt) >= 0)
            {
                long fs = 0; Guid fsK = MF_MT_FRAME_SIZE;
                try { nmt.GetUINT64(ref fsK, out fs); } catch {}
                if (fs > 0) { srcW = (int)(((ulong)fs) >> 32); srcH = (int)(((ulong)fs) & 0xFFFFFFFF); }
                Marshal.ReleaseComObject(nmt);
            }
            int scX = srcW / OUT_W;
            int scY = srcH / OUT_H;
            if (scX < 1) scX = 1;
            if (scY < 1) scY = 1;

            for (int i = 0; i < 30; i++)
            {
                int a2 = 0, f2 = 0; long t2 = 0; IMFSample ws = null;
                reader.ReadSample(FIRST_VIDEO, 0, out a2, out f2, out t2, out ws);
                if (ws != null) Marshal.ReleaseComObject(ws);
            }

            var results = new List<string>();
            bool infinite = (numSegments == 0);

            for (int seg = 1; infinite || seg <= numSegments; seg++)
            {
                string outPath = Path.Combine(outputDir, string.Format("segment_{0:D3}.avi", seg));

                var frames = new List<byte[]>();
                long segStartTs = -1;
                long segDur = segmentSecs * HNS_PER_SEC;
                int frameCounter = 0;

                while (!StopRequested)
                {
                    int actualStr = 0, flags = 0; long ts = 0; IMFSample s = null;
                    if (reader.ReadSample(FIRST_VIDEO, 0, out actualStr, out flags, out ts, out s) < 0 || s == null)
                        continue;
                    if (segStartTs < 0) segStartTs = ts;
                    long relTs = ts - segStartTs;
                    if (relTs >= segDur) { Marshal.ReleaseComObject(s); break; }

                    if (frameCounter % (30 / OUT_FPS) == 0)
                    {
                        byte[] raw = GetSampleBytes(s);
                        if (raw.Length >= srcW * srcH)
                            frames.Add(ScaleNV12ToRGB32(raw, srcW, srcH, OUT_W, OUT_H, scX, scY));
                    }
                    Marshal.ReleaseComObject(s);
                    frameCounter++;
                }

                if (frames.Count == 0) break;
                long fileSize = WriteAvi(outPath, frames, OUT_W, OUT_H, OUT_FPS);
                string segResult = string.Format("[+] seg{0:D3}: {1} frames, {2:F1} MB -> {3}", seg, frames.Count, fileSize / 1024.0 / 1024.0, Path.GetFileName(outPath));
                Console.WriteLine(segResult);
                results.Add(segResult.Substring(4));
                if (StopRequested) break;
            }

            Marshal.ReleaseComObject(reader);
            Marshal.Release(ps);
            act.ShutdownObject();
            Marshal.ReleaseComObject(act);

            return string.Join("|", results.ToArray());
        }
        catch (Exception ex) { return "EXCEPTION: " + ex.Message; }
        finally { try { MFShutdown(); } catch {} }
    }

    static byte[] GetSampleBytes(IMFSample s)
    {
        IMFMediaBuffer buf = null;
        if (s.ConvertToContiguousBuffer(out buf) < 0)
            s.GetBufferByIndex(0, out buf);
        IntPtr p; int maxL = 0, curL = 0;
        buf.Lock(out p, out maxL, out curL);
        byte[] data = new byte[curL];
        Marshal.Copy(p, data, 0, curL);
        buf.Unlock();
        Marshal.ReleaseComObject(buf);
        return data;
    }

    static byte[] ScaleNV12ToRGB32(byte[] nv12, int srcW, int srcH, int dstW, int dstH, int scX, int scY)
    {
        byte[] rgb = new byte[dstW * dstH * 4];
        int uvOff = srcW * srcH;
        for (int row = 0; row < dstH; row++)
        for (int col = 0; col < dstW; col++)
        {
            int sRow = row * scY, sCol = col * scX;
            int yi  = sRow * srcW + sCol;
            int ui  = uvOff + (sRow / 2) * srcW + (sCol & ~1);
            int Y   = nv12[yi];
            int Cb  = nv12[ui]     - 128;
            int Cr  = nv12[ui + 1] - 128;
            int r   = Clamp((int)(Y + 1.402    * Cr));
            int g   = Clamp((int)(Y - 0.344136 * Cb - 0.714136 * Cr));
            int b   = Clamp((int)(Y + 1.772    * Cb));
            int i   = (row * dstW + col) * 4;
            rgb[i]     = (byte)b;
            rgb[i + 1] = (byte)g;
            rgb[i + 2] = (byte)r;
            rgb[i + 3] = 0xFF;
        }
        return rgb;
    }

    static int Clamp(int v) { return v < 0 ? 0 : v > 255 ? 255 : v; }

    static long WriteAvi(string path, List<byte[]> frames, int w, int h, int fps)
    {
        int frameSize = w * h * 4;

        using (var fs = new FileStream(path, FileMode.Create))
        using (var bw = new BinaryWriter(fs))
        {
            bw.Write(0x46464952);
            long riffSzPos = fs.Position;
            bw.Write(0);
            bw.Write(0x20495641);

            int hdrlDataSz = 4 + (8 + 56) + (8 + 4 + (8 + 56) + (8 + 40));
            bw.Write(0x5453494C);
            bw.Write(hdrlDataSz);
            bw.Write(0x6C726468);

            bw.Write(0x68697661);
            bw.Write(56);
            bw.Write(1000000 / fps);
            bw.Write(frameSize * fps);
            bw.Write(0);
            bw.Write(0x0110);
            bw.Write(frames.Count);
            bw.Write(0);
            bw.Write(1);
            bw.Write(frameSize);
            bw.Write(w);
            bw.Write(h);
            bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0);

            int strlDataSz = 4 + (8 + 56) + (8 + 40);
            bw.Write(0x5453494C);
            bw.Write(strlDataSz);
            bw.Write(0x6C727473);

            bw.Write(0x68727473);
            bw.Write(56);
            bw.Write(0x73646976);
            bw.Write(0);
            bw.Write(0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write(0);
            bw.Write(1);
            bw.Write(fps);
            bw.Write(0);
            bw.Write(frames.Count);
            bw.Write(frameSize);
            bw.Write(-1);
            bw.Write(0);
            bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write((ushort)w); bw.Write((ushort)h);

            bw.Write(0x66727473);
            bw.Write(40);
            bw.Write(40);
            bw.Write(w);
            bw.Write(-h);
            bw.Write((ushort)1);
            bw.Write((ushort)32);
            bw.Write(0);
            bw.Write(frameSize);
            bw.Write(0); bw.Write(0);
            bw.Write(0); bw.Write(0);

            bw.Write(0x5453494C);
            long moviSzPos = fs.Position;
            bw.Write(0);
            bw.Write(0x69766F6D);
            long moviDataStart = fs.Position;

            var idx1Offsets = new List<int>();
            foreach (var frame in frames)
            {
                idx1Offsets.Add((int)(fs.Position - moviDataStart));
                bw.Write(0x63643030);
                bw.Write(frameSize);
                bw.Write(frame, 0, Math.Min(frame.Length, frameSize));
            }

            long moviEnd = fs.Position;
            long moviSz  = moviEnd - moviDataStart + 4;
            fs.Seek(moviSzPos, SeekOrigin.Begin);
            bw.Write((int)moviSz);
            fs.Seek(moviEnd, SeekOrigin.Begin);

            bw.Write(0x31786469);
            bw.Write(frames.Count * 16);
            for (int fi = 0; fi < frames.Count; fi++)
            {
                bw.Write(0x63643030);
                bw.Write(0x10);
                bw.Write(idx1Offsets[fi]);
                bw.Write(frameSize);
            }

            long totalSz = fs.Position;
            fs.Seek(riffSzPos, SeekOrigin.Begin);
            bw.Write((int)(totalSz - 8));

            return totalSz;
        }
    }
}
"@ -ErrorAction Stop

Write-Host "[*] Camera warming up, recording starts in ~1 second..."
Write-Host "[*] Each completed segment is printed below. Press Ctrl+C to stop."

$cancelHandler = [ConsoleCancelEventHandler] {
    param($s, $e)
    $e.Cancel = $true
    [MFVideo]::StopRequested = $true
    Write-Host "`n[*] Stop requested - finishing current segment..." -ForegroundColor Yellow
}
[Console]::add_CancelKeyPress($cancelHandler)

try {
    $result = [MFVideo]::RecordSegments($OutputDir, $SegmentSeconds, $NumSegments)
    if ($result -and ($result.StartsWith("EXCEPTION") -or $result.StartsWith("MF") -or $result.StartsWith("No "))) {
        Write-Host "[-] $result" -ForegroundColor Red
    }
} finally {
    [Console]::remove_CancelKeyPress($cancelHandler)
    Write-Host "[*] Recording stopped." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[T1125][MF Video] Done. Expected detections:"
Write-Host "  - mfplat.dll / mf.dll / mfreadwrite.dll loaded by powershell.exe"
Write-Host "  - MFEnumDeviceSources + IMFActivate.ActivateObject (camera open)"
Write-Host "  - MFCreateSourceReaderFromMediaSource + sustained ReadSample loop"
Write-Host "  - Multiple .avi files written consecutively to $OutputDir"
