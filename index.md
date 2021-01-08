# 统一认证api
------









#### java加密demo



```
package com.fdc.users.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by darren on 2020/3/32
 */
public class AESCode {

    //密钥算法
    public static final String KEY_ALGORITHM = "AES";
    //工作模式，填充模式
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    private static final String defaultCharset = "UTF-8";

    private String key;


    /**
     * 转换密钥
     *
     * @param key 二进制密钥
     * @return Key密钥
     */
    private static Key toKey(byte[] key) {
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        return secretKey;
    }

    /**
     * 解密
     */
    public static byte[] decrpyt(String d, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //字符串变为二进制
        byte[] data=parseHexStr2Byte(d);
        //还原密钥
        Key k = toKey(key);
        //实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //初始化
        cipher.init(Cipher.DECRYPT_MODE, k);
        //执行操作
        return cipher.doFinal(data);
    }

    /**
     * 加密
     */
    public static String encrypt(byte[] data, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //还原密钥
        Key k = toKey(key);
        //实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        //初始化
        cipher.init(Cipher.ENCRYPT_MODE, k);
        //执行操作

        return parseByte2HexStr(cipher.doFinal(data));
    }

    /**
     * 生成密钥
     */
    public static byte[] initKey() throws NoSuchAlgorithmException {

        return "9qSbHQCLNN0BDuOy".getBytes();
    }

    /**
     * 初始化密钥
     *
     * @return Base64编码密钥
     */
    public static String initKeyString() throws NoSuchAlgorithmException {
        return Base64.encodeBase64String(initKey());
    }

    /**
     * 获取密钥
     */
    public static byte[] getKey(String key) {
        return Base64.decodeBase64(key);
    }

    /**
     * 将二进制转换成16进制
     *
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }
    /**
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    /**
     * 解密
     *
     * @param data 待解密数据
     * @param key 密钥
     * @return byte[] 解密数据
     */
    public static byte[] decrypt(String data, String key)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrpyt(data, getKey(key));
    }

    /**
     * 加密
     *
     * @param data 待加密数据
     * @param key 密钥
     * @return byte[]加密数据
     */
    public static String encrypt(byte[] data, String key)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return encrypt(data, getKey(key));
    }

    /**
     * 摘要处理
     *
     * @param data 待摘要数据
     * @return 摘要字符串
     */
    public static String shaHex(byte[] data) {
        return DigestUtils.md5Hex(data);
    }

    /**
     * 验证
     *
     * @param data 待摘要数据
     * @param messageDigest 摘要字符串
     * @return 验证结果
     */
    public static boolean vailidate(byte[] data, String messageDigest) {
        return messageDigest.equals(shaHex(data));
    }


}



```
> 调用 
```
//加密
    String access_token="";
    try {
                access_token = AESCode.encrypt(code.getBytes(), auth.getSecret().getBytes());

            }catch (Exception e){
              
            }


//解密
       String mobile="";
    
        try {

            mobile = new String(AESCode.decrpyt(identity, auth.getSecret().getBytes()));

        }catch (Exception e){
             
        }
        
        
```

> 加密工具参考 http://tool.chacuo.net/cryptaes 

> 加密如图

![image](http://note.youdao.com/yws/res/24371/0FFC34FFDB6B4663B7859975A8FDAAFD)



## 1.注册发送验证码

#### 接口URL
> {{burl}}/servlet/authority?action=setInfo&command=identity&objectName=Authority&authority_type=1&authority_new=17610555589

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | setInfo | 必填 | 固定写法。 |
| command     | identity | 必填 | 固定写法。 |
| objectName     | Authority | 必填 | 固定写法。 |
| authority_type     | 1 | 必填 | 固定写法。 |
| authority_new     | 17610555589 | 必填 | 手机号。 |





#### 响应参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| code     | - |  必填 | 错误码 |
| message     | - |  必填 | 错误信息 |



## 2.输入验证码，输入密码完成注册

#### 接口URL
> {{burl}}/servlet/account?action=addInfo&objectName=Account&account_mobile=17610555589&account_password=17600736448&account_confirm=17600736448&active=8977&unionid=3213123

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | addInfo | 必填 | 固定写法。 |
| objectName     | Account | 必填 | 固定写法。 |
| account_mobile     | 17610555589 | 必填 | 手机号 |
| account_password     | 17600736448 | 必填 | 密码，明文 |
| account_confirm     | 17600736448 | 必填 | 密码，明文 |
| active     | 8977 | 必填 | 验证码 |
| unionid     | 3213123 | 选填 | 微信unionid |





#### 响应参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| code     | - |  必填 | 错误码 |
| message     | - |  必填 | 错误信息 |



## 3.密码模式登录

#### 接口URL
> {{burl}}/servlet/authorize?action=access&objectName=access&client-token=vgVigSJvFvdqpUGAsRrO&username=298F80B83148FB5851AFA54A3472E915&password=372BF232501651D9F01094AC16BA8F07&dynamic=1&grant_type=password&unionid=5031021

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | access | 必填 | 固定写法。 |
| objectName     | access | 必填 | 固定写法。 |
| client-token     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| username     | 298F80B83148FB5851AFA54A3472E915 | 必填 | 以授权秘钥，用aes加密的用户名/手机号/Email |
| password     | 372BF232501651D9F01094AC16BA8F07 | 必填 | 以授权秘钥，用aes加密的用户名/手机号/Email |
| dynamic     | 1 | 必填 | 固定写法。 |
| grant_type     | password | 必填 | 固定发法。 |
| unionid     | 5031021 | 选填 | 微信id |





#### 响应参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| code     | - |  必填 | 错误码 |
| message     | - |  必填 | 信息 |
| access_token     | - |  必填 | 登录之后的access_token，用于之后校验 |
| user_name     | - |  必填 | 用户名 |



## 4.登录之后读取用户

#### 接口URL
> {{burl}}/servlet/tobject?action=readInfo&objectName=User&clientToken=vgVigSJvFvdqpUGAsRrO&userToken=26E89286495D5E3AC3BF71D3DB6A905E8258017C5820BF83DA2966B4BCE477E2A70914FF9D2F946AA4090FCC306A1BDF

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | readInfo | 必填 | 固定写法。 |
| objectName     | User | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| userToken     | 26E89286495D5E3AC3BF71D3DB6A905E8258017C5820BF83DA2966B4BCE477E2A70914FF9D2F946AA4090FCC306A1BDF | 必填 | 登录所得的accees_token |








## 5.登录之后修改密码

#### 接口URL
> {{burl}}/servlet/tobject?action=setInfo&objectName=Account&clientToken=vgVigSJvFvdqpUGAsRrO&userToken=26E89286495D5E3AC3BF71D3DB6A905E8630B2ADA01CB330E29B65953DC91D9B628B6BC66561BAF6926B1ECB46B41007&account_pwd=17600736448&account_passwrd=17600736447

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | setInfo | 必填 | 固定写法。 |
| objectName     | Account | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| userToken     | 26E89286495D5E3AC3BF71D3DB6A905E8630B2ADA01CB330E29B65953DC91D9B628B6BC66561BAF6926B1ECB46B41007 | 必填 | 登录所得的accees_token |
| account_pwd     | 17600736448 | 必填 | 明文，旧密码 |
| account_passwrd     | 17600736447 | 必填 | 明文，新密码 |








## 6.登录之后修改用户名

#### 接口URL
> {{burl}}/servlet/tobject?action=setInfo&objectName=Account&clientToken=vgVigSJvFvdqpUGAsRrO&userToken=26E89286495D5E3AC3BF71D3DB6A905E28BBCB2446A08C7417A598151C215CBF628B6BC66561BAF6926B1ECB46B41007&account_fch=lijiaa

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | setInfo | 必填 | 固定写法。 |
| objectName     | Account | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| userToken     | 26E89286495D5E3AC3BF71D3DB6A905E28BBCB2446A08C7417A598151C215CBF628B6BC66561BAF6926B1ECB46B41007 | 必填 | 登录之后所得 |
| account_fch     | lijiaa | 必填 | 明文，新用户名 |
| account_passwrd     | 17600736447 | 必填 | - |








## 7.登录之后修改手机号或者Email

#### 接口URL
> {{burl}}/servlet/tobject?action=setInfo&objectName=Account&clientToken=vgVigSJvFvdqpUGAsRrO&userToken=26E89286495D5E3AC3BF71D3DB6A905E2E0BDD1375B3054AC7FF30F38823C1C6628B6BC66561BAF6926B1ECB46B41007&authority_old=&authority_new=darre94me@163.com&authority=2

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | setInfo | 必填 | 固定写法。 |
| objectName     | Account | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| userToken     | 26E89286495D5E3AC3BF71D3DB6A905E2E0BDD1375B3054AC7FF30F38823C1C6628B6BC66561BAF6926B1ECB46B41007 | 必填 | 登录之后获取的userToken。 |
| authority_old     | - | 必填 | 明文，老手机号或者Email |
| authority_new     | darre94me@163.com | 必填 | 明文，新手机号或者Email |
| authority     | 2 | 必填 | 1为手机号，2为Email |








## 8.找回密码发送验证码

#### 接口URL
> {{burl}}/servlet/resetPwd?action=ack&clientToken=vgVigSJvFvdqpUGAsRrO&identity=372bf232501651d9f01094ac16ba8f07

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | ack | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| identity     | 372bf232501651d9f01094ac16ba8f07 | 必填 | 以授权秘钥，用aes加密的手机号 |








## 9.找回密码发送验证码之后,校验

#### 接口URL
> {{burl}}/servlet/resetPwd?action=reset&clientToken=vgVigSJvFvdqpUGAsRrO&identity=372bf232501651d9f01094ac16ba8f07&ack-token=4096

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | reset | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| identity     | 372bf232501651d9f01094ac16ba8f07 | 必填 | 以授权秘钥，用aes加密的手机号 |
| ack-token     | 4096 | 必填 | 验证码 |








## 10.找回密码发送验证码之后,重置密码

#### 接口URL
> {{burl}}/servlet/resetPwd?action=reset&clientToken=vgVigSJvFvdqpUGAsRrO&identity=372bf232501651d9f01094ac16ba8f07&ack-token=6906&account_password=DB144A9FC84E6D1A8C0175BF6B8C4308

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | reset | 必填 | 固定写法。 |
| clientToken     | vgVigSJvFvdqpUGAsRrO | 必填 | 授权码 |
| identity     | 372bf232501651d9f01094ac16ba8f07 | 必填 | 以授权秘钥，用aes加密的手机号 |
| ack-token     | 6906 | 必填 | 明文，手机验证码 |
| account_password     | DB144A9FC84E6D1A8C0175BF6B8C4308 | 必填 | 以授权秘钥，用aes加密的密码 |








## 11.验证码登录，发送验证码

#### 接口URL
> {{burl}}/servlet/authority?action=setInfo&objectName=Authority&authority_new=17600736448&authority_type=1&command=dynamic

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | setInfo | 必填 | 固定写法。 |
| objectName     | Authority | 必填 | 固定写法。 |
| authority_new     | 17600736448 | 必填 | 固定写法。 |
| authority_type     | 1 | 必填 | 固定写法。 |
| command     | dynamic | 必填 | 固定写法。 |








## 12.验证码登录，校验验证码

#### 接口URL
> {{burl}}/servlet/authorize?action=access&grant_type=password&client-token=vgVigSJvFvdqpUGAsRrO&client_id=vgVigSJvFvdqpUGAsRrO&username=298F80B83148FB5851AFA54A3472E915&password=1FA996C7571CF4A91EE4383A3BFBDBC8&dynamic=1&unionid=503102

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| action     | access | 必填 | 固定写法。 |
| grant_type     | password | 必填 | 固定写法。 |
| client-token     | vgVigSJvFvdqpUGAsRrO | 必填 | 固定写法。 |
| client_id     | vgVigSJvFvdqpUGAsRrO | 必填 | 固定写法。 |
| username     | 298F80B83148FB5851AFA54A3472E915 | 必填 | 以授权秘钥，用aes加密的用户名/手机号/Email |
| password     | 1FA996C7571CF4A91EE4383A3BFBDBC8 | 必填 | 以授权秘钥，用aes加密的验证码 |
| dynamic     | 1 | 必填 | 固定写法 |
| unionid     | 503102 | 选填 | 微信id |





## 13.通过unionid获取用户信息

#### 接口URL
> {{burl}}/servlet/getInfoByUnionId?unionid=3213123

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| unionid     | 3213123 | 必填 | 微信id |



 

#### 14.通过userid 获取一条数据
> {{burl}}/user/getUserDetail?userid=1

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| userid     | 1 | 必填 | - |




#### 请求Header参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| accessToken     | ef0fda9387f04150be05057355838c5c |  必填 | - |


---


#### 15.通过userids 获取多条数据
> {{burl}}/user/getUsersDetail?userids=45,61

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| userid     | 45,61 | 必填 | - |




#### 请求Header参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| accessToken     | ef0fda9387f04150be05057355838c5c |  必填 | - |


> 注意 ， 是英文标点符号






## 1.获取商城端的用户信息

burl=  https://npai.fdcfabric.com


#### 通过userid 获取一条数据
> {{burl}}/user/getUserDetail?userid=1

#### 请求方式
> POST

#### Content-Type
> form-data

#### 请求Query参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| userid     | 1 | 必填 | - |




#### 请求Header参数

| 参数        | 示例值   | 是否必填   |  参数描述  |
| :--------   | :-----  | :-----  | :----  |
| accessToken     | 24d9612e9d144184acdf116914143444 |  必填 | - |


---

 









