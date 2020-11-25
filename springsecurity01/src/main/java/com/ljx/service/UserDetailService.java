package com.ljx.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.ljx.domain.Users;
import com.ljx.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 15:49
 * @Email 1129071273@qq.com
 */
@Service("userDetailsService")
public class UserDetailService implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 这里面接收的username 就是security界面传递的用户名
        QueryWrapper<Users> qw = new QueryWrapper<>();
        qw.eq("username",username);
        Users users = userMapper.selectOne(qw);
        if (users==null){
            //认证失败
            throw new UsernameNotFoundException("对不起 用户名不存在");
        }

        //如果涉及到数据库  根据name 查询数据库对应的数据
//        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale,ROLE_sale1");
        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_sale");
        return new User(users.getUsername(),new BCryptPasswordEncoder().encode(users.getPassword()),auths);
    }
}
