package com.ljx.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 15:29
 * @Email 1129071273@qq.com
 */

/**
 * SpringSecurity的配置类
 */
@Configuration
public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //在设置的userDetail里面返回用户名 密码 权限
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }
    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //配置没有权限的时候访问的界面
        http.exceptionHandling().accessDeniedPage("/norole.html");
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/test/hello").permitAll();
        http.formLogin()
                .loginPage("/login.html") //登录页面设置
                .loginProcessingUrl("/user/login") //自定义的登录访问路径  要与表单提交到地址一致
                .defaultSuccessUrl("/success.html").permitAll()//登录成功之后跳转的路径
                .and().authorizeRequests()
                .antMatchers("/","/test/hello","/user/login").permitAll()//设置那些路径不需要进行访问
//                .antMatchers("/test/index").hasAnyAuthority("admins,admin1")//设置当前的登录用户  只有具有了admins权限才能够访问这个路径
//                .antMatchers("/test/index").hasRole("sale")
                .antMatchers("/test/index").hasAnyRole("sale,sale1")
                .anyRequest().authenticated()
                .and().csrf().disable();//关闭csrf防护
    }
}
