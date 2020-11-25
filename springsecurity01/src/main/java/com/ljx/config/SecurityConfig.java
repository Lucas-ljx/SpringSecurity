package com.ljx.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 15:29
 * @Email 1129071273@qq.com
 */
//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String password = passwordEncoder.encode("123");
        //可以通过auth设置登录名与密码
        auth.inMemoryAuthentication().withUser("123").password(password).roles("admin");
    }
    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
    }
}
