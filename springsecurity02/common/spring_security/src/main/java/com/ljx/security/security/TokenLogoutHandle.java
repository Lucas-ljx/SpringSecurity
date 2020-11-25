package com.ljx.security.security;

import com.ljx.utils.R;
import com.ljx.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 李加喜
 * @date 2020/11/25 0025 0:28
 * @Email 1129071273@qq.com
 */
//退出处理器
public class TokenLogoutHandle implements LogoutHandler {
    //删除Token 根据token获取用户名在Redis里面进行删除
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenLogoutHandle(TokenManager tokenManager, RedisTemplate redisTemplate) {

        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        //在Header里面获取token
        // token不为空  移除token 从Redis删除token
        String token = request.getHeader("token");
        if (token!=null){
            //删除Token
            tokenManager.removeToken(token);
            //从Token获取用户名
            String username = tokenManager.getUserInfoFromToken(token);
            redisTemplate.delete(username);
        }
        ResponseUtil.out(response, R.ok());
    }
}
