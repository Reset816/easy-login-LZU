import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.*;

import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class params {
    String username;
    String password;
    String ip;
    String acid;
    String enc_ver;
    String token;

    String jQueryNUM;
    long time;

    String action;
    String chksum;
    String info;
    String n;
    String type;
    String os;
    String name;
    String double_stack;
}


public class main {
    private static void getChallenge(String url, params data) {
        data.jQueryNUM = Tools.getCallbackName();
        data.time = System.currentTimeMillis();
        HttpUrl URLtogetChallenge = new HttpUrl.Builder()
                .scheme("http")
                .host(url)
                .addPathSegment("cgi-bin")
                .addPathSegment("get_challenge")
                .addQueryParameter("callback", data.jQueryNUM + data.time)
                .addQueryParameter("username", data.username)
                .addQueryParameter("ip", data.ip)
                .addQueryParameter("_", String.valueOf(data.time + 2))
                .build();

        System.out.println(URLtogetChallenge);
        OkHttpClient OkHttpClient = new OkHttpClient.Builder().connectTimeout(3, TimeUnit.SECONDS).build();
        Request getChallenge = new Request.Builder()
                .get()
                .url(URLtogetChallenge)
                .build();

        Call call = OkHttpClient.newCall(getChallenge);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                //System.out.println("onResponse: " + response.body().string());
                //System.out.println(Tools.getjson(response.body().string()));
                //System.out.println(Tools.getjson());
                String enc = "srun_bx1";
                String n = "200";
                String type = "1";

                Pattern pattern = Pattern.compile("(?<=\\()[^\\)]+");
                Matcher matcher = pattern.matcher(response.body().string());
                String StringofgetChallenge = "";
                while (matcher.find()) {
                    StringofgetChallenge = (matcher.group());
                }
                System.out.println(StringofgetChallenge);
                //test
                //StringofgetChallenge = "{\"challenge\":\"4242cd7850e9ad2dabe6c9b3ae14994a9f50c1a9305f7f4b0fe32c3acfad037e\",\"client_ip\":\"172.23.37.242\",\"ecode\":0,\"error\":\"ok\",\"error_msg\":\"\",\"expire\":\"51\",\"online_ip\":\"172.23.37.242\",\"res\":\"ok\",\"srun_ver\":\"SRunCGIAuthIntfSvr V1.18 B20200522\",\"st\":1590846311}";
                //
                JsonObject convertedObject = new Gson().fromJson(StringofgetChallenge, JsonObject.class);

                data.ip = convertedObject.get("client_ip").getAsString();
                data.token = convertedObject.get("challenge").getAsString();
                //Attention that some AP's acid is 1
                data.acid = "2";

//                构造i 这样构建出来的json是乱序的，不可行
//                JSONObject infoin = new JSONObject();
//                infoin.put("username", data.username);
//                infoin.put("password", data.password);
//                infoin.put("ip", data.ip);
//                infoin.put("acid", "2");
//                infoin.put("enc_ver", enc);
//                System.out.println(JSON.toJSONString(infoin));
//                String i = Tools.info(JSON.toJSONString(infoin), data.token);

                //info(d, k)
                String d = "{\"username\":\"" + data.username + "\",\"password\":\"" + data.password + "\",\"ip\":\"" + data.ip + "\",\"acid\":\"2\",\"enc_ver\":\"srun_bx1\"}";
                //test
                //错误 String test ="{username:\"tany18\",password:\"Ty15228855340\",ip:\"219.246.90.168\",acid:\"2\",enc_ver:\"srun_bx1\"}";
                //正确 String test ="{\"username\":\"tany18\",\"password\":\"Ty15228855340\",\"ip\":\"219.246.90.168\",\"acid\":\"2\",\"enc_ver\":\"srun_bx1\"}"
                //System.out.println(d);
                String i = Tools.info(d, data.token);
                //System.out.println(i);
                String hmd5 = Tools.pwd(data.password, data.token);

                String chkstr = data.token + data.username;
                chkstr += data.token + hmd5;
                chkstr += data.token + data.acid;
                chkstr += data.token + (data.ip);
                chkstr += data.token + n;
                chkstr += data.token + type;
                chkstr += data.token + i;

                data.password = "{MD5}" + hmd5;
                data.action = "login";
                data.chksum = Tools.chksum(chkstr);
                data.info = i;
                data.n = n;
                data.type = type;
                data.os = "Macintosh";
                data.name = "Macintosh";
                data.double_stack = "0";//??????????????

                srunPortal(url, data);
            }
        });
    }

    private static void srunPortal(String url, params data) {
        HttpUrl URLtosrunPortal = new HttpUrl.Builder()
                .scheme("http")
                .host(url)
                .addPathSegment("cgi-bin")
                .addPathSegment("srun_portal")
                .addQueryParameter("callback", data.jQueryNUM + data.time)
                .addQueryParameter("action", data.action)
                .addQueryParameter("username", data.username)
                .addQueryParameter("password", data.password)
                .addQueryParameter("ac_id", data.acid)
                .addQueryParameter("ip", data.ip)
                .addQueryParameter("chksum", data.chksum)
                .addQueryParameter("info", data.info)
                .addQueryParameter("n", data.n)
                .addQueryParameter("type", data.type)
                .addQueryParameter("os", data.os)
                .addQueryParameter("name", data.name)
                .addQueryParameter("double_stack", data.double_stack)
                .addQueryParameter("_", String.valueOf(data.time + 3))
                .build();
        System.out.println(URLtosrunPortal);
        OkHttpClient OkHttpClient = new OkHttpClient.Builder().connectTimeout(3, TimeUnit.SECONDS).build();
        Request getsrunPortal = new Request.Builder()
                .get()
                .url(URLtosrunPortal)
                .build();

        Call call = OkHttpClient.newCall(getsrunPortal);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                System.out.println(response.body().string());
            }
        });
    }

    public static void main(String[] args) {
        String url = "10.10.0.166";
        params data = new params();
//        //change the data.username, data.password, data.ip into your own.
//        data.username = "tany18";
//        data.password = "test";
//        data.ip = "172.23.91.182";
        Scanner in = new Scanner(System.in);
        System.out.println("Type in your username:");
        data.username = in.nextLine();
        System.out.println("Type in your password:");
        data.password = in.nextLine();
        System.out.println("Type in your local ip:");
        data.ip = in.nextLine();

        //http://10.10.0.166/cgi-bin/get_challenge?callback=jQuery1124004853879047803211_1590655764103&username=tany18&ip=172.23.37.242&_=1590655764105
        //http://10.10.0.166/cgi-bin/srun_portal?callback=jQuery1124004853879047803211_1590655764103&action=login&username=tany18&password=%7BMD5%7D09316a2c25328a1c0b14027d2065c243&ac_id=2&ip=172.23.37.242&chksum=5e0ee0e90001e5a13ccfda630affeab5c079291e&info=%7BSRBX1%7DwRu2XMBCbBhQE5%2Bk%2B6p9wW1wkVTCzfbG%2FDMozoDFfLzljVJemHy1HWr6VpGrahjPzu%2FqlsPSld%2Fp1g9SbOJKq0AQHMnzoVY2VxcEYk%2B0XpbE0hZksEa7pcsZw4uGDFD2CbR6T1gEYvak2QnW&n=200&type=1&os=Windows+10&name=Windows&double_stack=0&_=1590655764106
        //http://10.10.0.166/srun_portal_success?ac_id=2&theme=lzu&srun_domain=

        //getChallenge
        getChallenge(url, data);
    }
}
