package com.ljx.security.filter;

import com.ljx.security.entry.SecurityUser;
import com.ljx.security.entry.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ljx.security.security.TokenManager;
import com.ljx.utils.R;
import com.ljx.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author 李加喜
 * @date 2020/11/25  0:27
 * @Email 1129071273@qq.com
 */
//认证过滤  指定就是进行认证登录
public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private AuthenticationManager authenticationManager;


    public TokenLoginFilter(TokenManager tokenManager, RedisTemplate redisTemplate, AuthenticationManager authenticationManager) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
        this.setPostOnly(false);
        //设置登录的路径和提交方式
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/admin/acl/login","POST"));
    }
    //获取表单提交的用户名和密码
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword(),new ArrayList<>()));

        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    //认证成功调用的方法
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 认证成功  得到认证成功之后用户信息
        SecurityUser user = (SecurityUser)authResult.getPrincipal();
        //根据用户名生成token
        String token = tokenManager.createToken(user.getCurrentUserInfo().getUsername());
        //将用户名和用户权限放到权限列表里面
        redisTemplate.opsForValue().set(user.getCurrentUserInfo().getUsername(),user.getPermissionValueList());
        //返回token
        ResponseUtil.out(response, R.ok().data("token",token));
    }
    //认证失败调用的方法
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ResponseUtil.out(response,R.error());
    }
}
