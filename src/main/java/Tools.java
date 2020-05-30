import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

//@author MaPl
public class Tools {
    public static void main(String[] args) {
        // 测试用例
        System.out.println(Tools.l(Tools.s("abcdefg", true), true));
        System.out.println((int) Tools.xEncode("abcdef", "abcdef").charAt(0));
        System.out.println(xBase64(Tools.xEncode("abcdefgh123", "abcdefgh")));
        System.out.println(getCallbackName());
        System.out.println(info("{\"a\":1}", "4678")); // 预期结果{SRBX1}iQlGper7tf9GENbo
        System.out.println(pwd("123", "456")); // 预期结果de0f380e163230391138f482b3cfe997
        System.out.println(chksum("123456")); // 预期结果7c4a8d09ca3762af61e59520943dc26494f8941b
    }


    /**
     * info函数实现, 参数要传json字符串
     *
     * @param jsonString json字符串
     * @param key        密钥, 即challenge
     * @return 一个字符串
     * @author MaPl
     */
    public static String info(String jsonString, String key) {
        return "{SRBX1}" + xBase64(xEncode(jsonString, key));
    }

    /**
     * pwd函数实现, 即Hmac-md5
     *
     * @param str 字符串
     * @param key 密钥字符串
     * @return 一个字符串, 出现异常返回""
     * @author MaPl
     */
    public static String pwd(String str, String key) {
        try {
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacMD5");
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            return byteArrayToHexString(mac.doFinal(str.getBytes()));
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * chksum函数实现, 即sha-1
     *
     * @param str 字符串
     * @return 一个字符串, 出现异常返回""
     * @author MaPl
     */
    public static String chksum(String str) {
        try {
            MessageDigest mDigest = MessageDigest.getInstance("SHA1");
            byte[] result = mDigest.digest(str.getBytes());
            return byteArrayToHexString(result);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 生成回调名
     *
     * @return 回调名
     * @author MaPl
     */
    public static String getCallbackName() {
        //return "jQuery" + ("1.12.4" + Math.random()).replaceAll("\\D", "") + "_" + (System.currentTimeMillis() + 1);
        return "jQuery" + ("1.12.4" + Math.random()).replaceAll("\\D", "") + "_";
    }

    /**
     * 登录页面魔改版base64实现
     *
     * @param str 字符串
     * @return 更换字母表的base64
     * @author MaPl
     */
    public static String xBase64(String str) {
        // 改编自https://blog.csdn.net/zzhouqianq/article/details/46992347
        byte[] ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA=".getBytes();
        byte[] out = new byte[((str.length() + 2) / 3) * 4];
        for (int i = 0, index = 0; i < str.length(); i += 3, index += 4) {
            boolean quad = false;
            boolean trip = false;
            int val = (0xFF & str.charAt(i));
            val <<= 8;
            if ((i + 1) < str.length()) {
                val |= (0xFF & str.charAt(i + 1));
                trip = true;
            }
            val <<= 8;
            if ((i + 2) < str.length()) {
                val |= (0xFF & str.charAt(i + 2));
                quad = true;
            }
            out[index + 3] = ALPHABET[(quad ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 2] = ALPHABET[(trip ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 1] = ALPHABET[val & 0x3F];
            val >>= 6;
            out[index + 0] = ALPHABET[val & 0x3F];
        }
        return new String(out);
    }

    /**
     * xEncode加密算法
     *
     * @param str 字符串
     * @param key 密钥
     * @return 不可读的字符串
     * @author MaPl
     */
    public static String xEncode(String str, String key) {
        if (str == "") {
            return "";
        }
        int[] v = s(str, true);
        int[] k = s(key, false);
        int n = v.length - 1;
        int z = v[n], y = v[0], c = 0x86014019 | 0x183639A0, m, e, p, q = (int) Math.floor(6 + 52 / (n + 1)), d = 0;
        while (0 < q--) {
            d = d + c & (0x8CE0D9BF | 0x731F2640);
            e = d >>> 2 & 3;
            for (p = 0; p < n; p++) {
                y = v[p + 1];
                m = z >>> 5 ^ y << 2;
                m += (y >>> 3 ^ z << 4) ^ (d ^ y);
                m += ((p & 3) ^ e) < k.length ? k[(p & 3) ^ e] ^ z : 0 ^ z;
                z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
            }
            y = v[0];
            m = z >>> 5 ^ y << 2;
            m += (y >>> 3 ^ z << 4) ^ (d ^ y);
            m += ((p & 3) ^ e) < k.length ? k[(p & 3) ^ e] ^ z : 0 ^ z;
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD);
        }
        return l(v, false);
    }

    /**
     * 将字符串转为int数组
     *
     * @param a 字符串
     * @param b 是否在最后附加字符串长度
     * @return int数组
     * @author MaPl
     */
    private static int[] s(String a, boolean b) {
        int c = a.length();
        int[] v;
        if (!b) {
            v = new int[(c + 3) >> 2]; // 字符串长度除以4, 向下取整
        } else {
            v = new int[((c + 3) >> 2) + 1]; // b为真在数组最后加一个字符串长度, 注意运算符优先级
        }
        int i;
        for (i = 0; i < c - 4; i += 4) {
            v[i >> 2] = a.charAt(i) | a.charAt(i + 1) << 8 | a.charAt(i + 2) << 16 | a.charAt(i + 3) << 24;
        }
        // 最后一组特殊处理(避免数组越界)
        for (int j = 0; j < c - i; j++) {
            v[i >> 2] = v[i >> 2] | a.charAt(i + j) << (j << 3);
        }
        if (b) {
            v[v.length - 1] = c;
        }
        return v;
    }

    /**
     * 将int数组转为字符串
     *
     * @param a int数组
     * @param b 是否在最后附加字符串长度
     * @return 字符串
     * @author MaPl
     */
    private static String l(int[] a, boolean b) {
        int d = a.length;
        int c = (d - 1) << 2;
        String[] t = new String[d];
        if (b) { // 校验附加的长度是否正确
            int m = a[d - 1];
            if ((m < c - 3) || (m > c)) {
                return null; // return null警告
            }
            c = m; // 订正字符串长度
        }
        for (int i = 0; i < d; i++) {
            t[i] = new String(new char[]{(char) (a[i] & 0xff), (char) (a[i] >>> 8 & 0xff),
                    (char) (a[i] >>> 16 & 0xff), (char) (a[i] >>> 24 & 0xff)});
        }
        if (b) {
            return String.join("", t).substring(0, c);
        } else {
            return String.join("", t);
        }
    }

    /**
     * 字节数组转hex格式字符串
     *
     * @param b 字节数组
     * @return 一个字符串
     * @author MaPl
     */
    private static String byteArrayToHexString(byte[] b) {
        // 参考自https://blog.csdn.net/g1506490083/java/article/details/81567474
        StringBuffer sb = new StringBuffer(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

}