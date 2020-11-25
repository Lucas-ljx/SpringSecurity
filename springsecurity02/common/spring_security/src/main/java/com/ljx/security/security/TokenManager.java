package com.ljx.security.security;

import io.jsonwebtoken.*;
import org.omg.CORBA.PUBLIC_MEMBER;

import java.util.Date;

/**
 * @author 李加喜
 * @date 2020/11/25 0025 0:28
 * @Email 1129071273@qq.com
 */
// token操作工具类
public class TokenManager {
    //token有效时长
    private long tokenEcpiration=24*60*60*100;
    //编码秘钥
    private String tokenSignKey="123456";
    //根据用户名生成Token
    public String createToken(String username){
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis()+tokenEcpiration))
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
        return token;
    }
    //根据Token得到用户信息
    public  String getUserInfoFromToken(String token){
        String userInfo = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
        return userInfo;
    }
    //删除Token
    public void removeToken(String token){}
}
