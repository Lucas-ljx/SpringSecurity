package com.ljx.security.security;

import com.ljx.utils.R;
import com.ljx.utils.ResponseUtil;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 李加喜
 * @date 2020/11/25 0025 0:29
 * @Email 1129071273@qq.com
 */
//未授权统一处理类
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        ResponseUtil.out(response, R.error());
    }
}
