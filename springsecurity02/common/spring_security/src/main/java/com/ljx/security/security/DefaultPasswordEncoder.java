package com.ljx.security.security;

import com.ljx.utils.MD5;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author 李加喜
 * @date 2020/11/25 0025 0:28
 * @Email 1129071273@qq.com
 */
//密码处理工具类
public class DefaultPasswordEncoder implements PasswordEncoder {
    public DefaultPasswordEncoder(){
        this(-1);
    }
    public DefaultPasswordEncoder (int strength){

    }
    //实现加密  进行MD5加密
    @Override
    public String encode(CharSequence charSequence) {
        MD5.encrypt(charSequence.toString());
        return null;
    }
    //进行比对

    /**
     *
     * @param charSequence  传入的密码
     * @param encodingPassword 加密之后的密码
     * @return
     */
    @Override
    public boolean matches(CharSequence charSequence, String encodingPassword) {
        return encodingPassword.equals(MD5.encrypt(charSequence.toString()));
    }
}
