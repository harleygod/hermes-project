// HessianLab — gen/read 双模式反序列化靶机模板
//
// 用法:
//   1) 改 PKG 为目标白名单包前缀（如 com.dahua.evo.audit）—— 载体类必须落在白名单内
//   2) lib/ 放【同版本】hessian jar + 目标白名单实现的依赖（如 slf4j）
//   3) src/ 放目标的【真实】白名单实现与 Serializer 源码（不要自己重写等价物）
//   4) javac -encoding UTF-8 -cp 'lib/*' -d out $(find src -name "*.java")
//   5) java -Dprobe.tag=GEN -cp 'out;lib/*' audit.HessianLab gen     # 打 payload
//      java -Dprobe.tag=LAB -cp 'out;lib/*' audit.HessianLab read    # 靶机侧反序列化
//
// 设计要点:
//   * 探针类 static 块写 STATIC_BLOCK_HIT.txt，内容带 -Dprobe.tag → 区分生成端/靶机端触发（否则自欺）
//   * gen 用默认 SerializerFactory（生成端不查白名单）；read 用目标白名单 → 复现服务端真实行为
//   * 每条 payload 输出 "readObject() 返回: <实际类名>"，这就是判定依据
//   * 副作用打印 [SIDE-EFFECT] ...（在探针/Comparable/readResolve 里埋打印）

package audit;

import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.TreeMap;
import java.util.concurrent.SynchronousQueue;

public class HessianLab {

    static final String DIR = "payloads/";

    // ------------------------------------------------------------------
    // 探针类：证明"类被加载/初始化"，tag 区分生成端 vs 靶机端
    // 放在【非白名单】包里 —— 扮演"目标 classpath 上任意一个类"的角色
    // ------------------------------------------------------------------
    public static class ProbeStatic {
        static {
            try {
                String tag = System.getProperty("probe.tag", "unknown");
                // ★ 注意: 这里必须能被识别为侧信道
                String info = "STATIC_BLOCK_EXECUTED tag=" + tag
                        + " time=" + new java.util.Date()
                        + " pid=" + java.lang.management.ManagementFactory.getRuntimeMXBean().getName()
                        + System.lineSeparator();
                FileWriter fw = new FileWriter("STATIC_BLOCK_HIT.txt", true);
                fw.write(info);
                fw.close();
                System.out.println("[probe] >>>>>> STATIC BLOCK EXECUTED (tag=" + tag + ") <<<<<<");
            } catch (Throwable t) {
                System.out.println("[probe] error: " + t);
            }
        }
        public static final String MARKER = "probe-loaded";
    }

    // ------------------------------------------------------------------
    // 非白名单普通 POJO（对照组：验证白名单是否降级）
    // ------------------------------------------------------------------
    public static class NotAllowedBean implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        public String name = "plain";
        public int num = 1;
        public Object readResolve() {                       // 副作用探针
            System.out.println("[SIDE-EFFECT] NotAllowedBean.readResolve");
            return this;
        }
        public String toString() { return "NotAllowedBean(name=" + name + ", num=" + num + ")"; }
    }

    // ------------------------------------------------------------------
    // 白名单载体类：包名必须命中目标白名单通配（示例 com.dahua.evo.*）
    // 字段刻意复刻真实危险字段：Class / Method / 非白名单类型
    // ------------------------------------------------------------------
    public static class EvoHolderBean implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        public String n = "holder";
        public Class clazz;                 // 组 A/B: Class 类型字段
        public Method method;               // 组 B: Method 字段（预期生成端失败）
        public NotAllowedBean b;            // ★ 组 C: 非白名单【声明类型】字段 —— 突破口
    }

    // 白名单内 Comparable：用于组 D（集合元素 compareTo 触发）
    public static class EvoComparable implements Comparable<EvoComparable>, java.io.Serializable {
        private static final long serialVersionUID = 1L;
        public int v;
        public EvoComparable() {}
        public EvoComparable(int v) { this.v = v; }
        public int compareTo(EvoComparable o) {
            System.out.println("[SIDE-EFFECT] EvoComparable.compareTo");
            return Integer.compare(this.v, o.v);
        }
        public int hashCode() { System.out.println("[SIDE-EFFECT] EvoComparable.hashCode"); return v; }
        public String toString() { return "EvoComparable(" + v + ")"; }
    }

    // ------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "gen".equals(args[0])) {
            gen("control_plainbean", new NotAllowedBean());
            gen("v2_class_obj", ProbeStatic.class);                       // Class 对象（任意类名）
            EvoHolderBean hb = new EvoHolderBean();
            hb.clazz = ProbeStatic.class;
            hb.b = new NotAllowedBean();                                  // ★ 组 C
            gen("v3_holder_nonallowed_field", hb);
            try {                                                          // 组 B: 预期失败
                EvoHolderBean h2 = new EvoHolderBean();
                h2.method = Runtime.class.getMethod("exec", String.class);
                gen("v4_holder_method_field", h2);
            } catch (Throwable t) {
                System.out.println("  [gen] v4 生成失败(预期): " + t.getMessage());
            }
            gen("v5_control_synchronousqueue", new SynchronousQueue<Object>());
            PriorityQueue<EvoComparable> pq = new PriorityQueue<EvoComparable>();
            pq.add(new EvoComparable(5));
            pq.add(new EvoComparable(1));
            gen("v6_priorityqueue_compareto", pq);
            TreeMap<EvoComparable, String> tm = new TreeMap<EvoComparable, String>();
            tm.put(new EvoComparable(3), "three");
            gen("v7_treemap_compareto", tm);
            System.out.println("GEN done");
        } else {
            for (String n : new String[]{
                    "control_plainbean", "v2_class_obj", "v3_holder_nonallowed_field",
                    "v4_holder_method_field", "v5_control_synchronousqueue",
                    "v6_priorityqueue_compareto", "v7_treemap_compareto"}) {
                read(n);
            }
        }
    }

    static void gen(String name, Object o) throws Exception {
        Hessian2Output out = new Hessian2Output(new FileOutputStream(DIR + name + ".bin"));
        out.writeObject(o);
        out.close();
        System.out.println("  [gen] " + name + ".bin  顶层类型=" + (o == null ? "null" : o.getClass().getName()));
    }

    static void read(String name) {
        try {
            Hessian2Input in = new Hessian2Input(new FileInputStream(DIR + name + ".bin"));
            // ★ 换成目标的真实白名单实现；等价物自己写会导致结论不可信
            in.setSerializerFactory(new com.dahua.evo.rpc.serialize.impl.CustomSerializerFactory());
            Object o = in.readObject();
            String extra = "";
            if (o instanceof EvoHolderBean) {
                EvoHolderBean h = (EvoHolderBean) o;
                extra = "  [field b -> " + cls(h.b) + " = " + h.b
                        + " ; field clazz -> " + (h.clazz == null ? "null" : h.clazz.getName()) + "]";
            }
            System.out.println(pad(name) + " -> " + cls(o) + "   " + trim(String.valueOf(o)) + extra);
        } catch (Throwable t) {
            System.out.println(pad(name) + " -> EXCEPTION " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    static String cls(Object o) { return o == null ? "null" : o.getClass().getName(); }

    static String trim(String s) {
        s = s.replace("\r", " ").replace("\n", " ");
        return s.length() > 60 ? s.substring(0, 60) + "..." : s;
    }

    static String pad(String s) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < 32) b.append(' ');
        return b.toString();
    }
}
