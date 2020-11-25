## Spring Security你懂了吗

前置知识

- 掌握Spring框架
- 掌握SpringBoot框架
- 掌握JavaWeb框架

下面的内容主要是用来介绍用户**认证**和用户的**授权**

两个安全认证框架对比

SpringSecurity

- 能够和Spring进行无缝整合
- 全面的权限控制
- 专门为Web开发而设计的
  -  旧版本不能脱离 Web 环境使用
  - 新版本对整个框架进行了分层抽取，分成了核心模块和 Web 模块。单独
    引入核心模块就可以脱离 Web 环境

Shiro

是一款轻量级的权限控制框架

- 轻量级。 Shiro 主张的理念是把复杂的事情变简单。针对对性能有更高要求
  的互联网应用有更好表现
- 通用性
  - 好处 不局限于 Web 环境，可以脱离 Web 环境使用。
  - 坏处 在 Web 环境下一些特定的需求需要手动编写代码定制

**用户认证**

简单的说指定就是系统认为用户是否能登录

**用户授权**

指定就是系统判断用户是否具有权限去做某些事情

SpringSecurity小测试

配置环境

```xml
   		<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

```

编写Controller

```java
@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("/hello")
    public String add(){
        return "Hello Spring Security";
    }
}
```

此时启动服务进行登录之后  会出现安全认证界面

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\安全认证图片1.png)

<font color="red">注意   </font>这里的用户名默认是user 密码会在控制台打印出来

**SpringSecurity基本原理**

SpringSecurity本质是过滤器链  本文主要讲解三个过滤器

- FilterSecurityInterceptor是一个方法级的权限过滤器, 基本位于过滤链的最底部

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\底层1.png)

具体invoke方法的实现

super.beforeInvocation(fi) 表示查看之前的 filter 是否通过。

fi.getChain().doFilter(fi.getRequest(), fi.getResponse());表示真正的调用后台的服务

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\底层2.png)

- ExceptionTranslationFilter: 是一个异常过滤器，用来处理在认证授权的过程总抛出的异常

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\底层3.png)

- UsernamePasswordAuthenticationFilte 实现对/login的POST请求的拦截，检验表单中用户名与密码

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\底层4.png)



用户自定义开发的时候不能用户名与密码都是涉及数据库的  所以在自定义开发中设计到的两个重要地接口

- UserDetailsService  用来查询数据库的用户名和密码的过程

创建类继承UsernamePasswordAuthenticationFilte ，重写attemptAuthentication successfulAuthentication unsuccessfulAuthentication三个方法

创建类实现UserDetailsService 编写查询数据库的过程，返回User对象 这个User对象是安全框架提供的对象

- PasswordEncoder

对密码进行解密

Web权限方案

- 认证

  - 第一种  通过配置类来实现

    ```properties
    spring.security.user.name=123
    spring.security.user.password=123
    ```

  - 第二种  通过配置类来实现

    ```java
    @Configuration
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
    ```

  - 第三种  自定义编写实现类

    - 创建配置类 设置使用哪个userDetailService实现类

    - 编写实现类 返回User对象 User对象有用户名 买吗和操作权限

      ```java
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
      }
      @Service("userDetailsService")
      public class UserDetailService implements UserDetailsService {
          @Override
          public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
              //如果涉及到数据库  根据name 查询数据库对应的数据
              List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
              return new User("ljx",new BCryptPasswordEncoder().encode("123"),auths);
          }
      }
      ```

**连接数据库 完成用户的认证**

添加pom.xml文件

```xml
		<dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.2.0</version>
        </dependency>
        <dependency>
            <groupId>mysql</ groupId>
            <artifactId>mysql-connector-java</ artifactId>
        </ dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
```

设置实体类 (包含username和password)

创建UserMapper继承BaseMapper<Users> 

 在UserDetailService里面根据传入的用户名获取对应的数据库对象  进行判断

```java
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
        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
        return new User(users.getUsername(),new BCryptPasswordEncoder().encode(users.getPassword()),auths);
    }
}
```

**自定义登录页面以及设置哪些访问不需要设置就能实现访问**

在配置类里面设置过滤规则

```java
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
        http.formLogin()
                .loginPage("/login.html") //登录页面设置
                .loginProcessingUrl("/user/login")//自定义的登录访问路径要与表单提交到地址一致
                .defaultSuccessUrl("/test/index").permitAll()//登录成功之后跳转的路径
                .and().authorizeRequests()
                .antMatchers("/","/test/hello","/user/login").permitAll()
                 //设置那些路径不需要进行访问
                .anyRequest().authenticated()
                .and().csrf().disable();//关闭csrf防护
    }
}
```

设置默认的登录界面 路径resourcess/statis/login.html

启动测试:

localhost:8111/test/hello==>得到输出结果

localhost:8111/test/index==>就会跳转到登录界面 然后进行登录 就能够得到对应的返回值

**基于角色或权限进行访问控制**

**hasAuthority**

如果当前的用户具有指定的权限那么返回true 否则返回false

- 在配置类里面设置哪些路径需要指定权限

- 在UserDetailsService里面 把返回User对象设置权限

- ```java
  在配置类中
  .antMatchers("/test/index").hasAuthority("admins")//设置当前的登录用户  只有具有了admin权限才能够访问这个路径
  ```

- ```java
  在UserDetailsService中
  List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins");
  ```

**hasAnyAuthority**

如果当前的主体有任何任何的角色的话返回true

```java
hasAnyAuthority("admins,admin1")
```

**hasRole**

如果用户具备给定的角色就允许访问否则出现403

```java
.antMatchers("/test/index").hasRole("sale")
    底层会在sale前面加ROLE_sale
 所以 
 List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale");
```

**hasAnyRole**

如果允许具备的多个角色就允许访问  否则403

```java
.antMatchers("/test/index").hasAnyRole("sale,sale1")
   
List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admins,ROLE_sale,ROLE_sale1");
注意:在设置角色的底层会默认为其加上ROLE_ 所以在为用户赋予角色的时候也要加上ROLE_
```

**自定义403没有权限的界面**

```java
在配置类里面
http.exceptionHandling().accessDeniedPage("/norole.html");
```

**认证授权中注解的使用**

使用注解要先开启注解的功能

@ Secured 

先开启注解功能@EnableGlobalMethodSecurity(securedEnabled=true)

判断是否具有角色，另外需要注意的是这里匹配的字符串需要添加前缀“ROLE_“

在控制器上也可以在方法上 针对于某一个方法

```java
@RestController
@RequestMapping("/test")
//@Secured({"ROLE_admin123"})

只有在UserDetails里面为用户设置了权限才能够进行访问
List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_admin123");
```

@PreAuthrorize

开启注解@EnableGlobalMethodSecurity(prePostEnabled = true)

作用在方法上

注解适合进入方法前的权限验证,可以将登录用户的 roles/permissions 参数传到方法中

```java
在方法上设置
@PreAuthorize("hasAnyAuthority('admin')")
在UserDetails设置
List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");
```

@**PostAuthorize**

开启注解@EnableGlobalMethodSecurity(prePostEnabled = true)

在方法执行之后进行执行  基本不用  方法之后检验还有啥作用

```java
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
在方法上设置
@PostAuthorize("hasAnyAuthority('admin')")
在UserDetails设置
List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");
```

**@PostFilter**

权限认证之后，对返回的数据进行过滤

```java
@GetMapping("getAll")
@PreAuthorize("hasRole('ROLE_ 管理员')")
@PostFilter("filterObject.username == 'admin1'")
public List<UserInfo> getAllUser(){
ArrayList<UserInfo> list = new ArrayList<>();
list.add(new UserInfo(1l,"admin1","6666"));
list.add(new UserInfo(2l,"admin2","888"));
return list;
}
只返回username为admin1的数据
```

 **@PreFilter**

对进入控制器之前的数据进行过滤

```java
@RequestMapping("getTestPreFilter")
@PreAuthorize("hasRole('ROLE_ 管理员')")
@PreFilter(value = "filterObject.id%2==0")
public List<UserInfo> getTestPreFilter(@RequestBody List<UserInfo>list){
list.forEach(t-> {
System.out.println(t.getId()+"\t"+t.getUsername());
});
return list;
}
只有list集合里面Id的值是偶数的才会进入
```

**登录之后用户的注销或者退出操作**

在配置类里面添加配置退出的映射

```java
http.logout().logoutUrl("/logout").logoutSuccessUrl("/test/hello").permitAll();
此时修改一下 登录成功的跳转界面 
.defaultSuccessUrl("/success.html").permitAll()//登录成功之后跳转的路径
在success.html里面
<a href="/logout">退出</a>
```

**CSRF**

跨站请求伪造,默认情况下回启动CSRF保护,以防止CSRF攻击应用,SpringSecurity会针对PATCH POST PUT DELETE方法进行防护

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\认证token.png)

**SpringSecurity微服务权限方案**

- 基于Session 那么Spring-Security会对cookie里面的sessionId进行解析,找到服务器存储的session信息,然后判断当前的用户是否符合请求的要求
- 如果是token 那么就要解析出token然后将当前请求加入到Spring-Security管理的权限信息中

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\认证过程.png)



用户登录成功之后 查询对应的用户权限列表--->将用户相关信息保存在Redis里面(Key:用户名  value:用户的权限列表)--->根据用户名生成token(使用JWT)--->将token放到cookie里面  在header放token---->Spring Security 从header中获取token 那token获取用户名  那这个用户名查询对应的权限列表(Redis里面)

**微服务权限管理案例的主要功能**

1. 登录(人证 )
2. 添加角色
3. 为角色分配菜单
4. 添加用户
5. 为用户分配角色

**权限管理数据模型**

菜单表   角色菜单表  角色表   用户角色表  用户表

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\权限关系表.png)



**案例涉及到的技术**

Maven SpringBoot MybatisPlus SpringCloud(GetWay  Nacos)  Redis Swagger

创建一个父工程: acl_parent  管理依赖的版本

在父工程下面创建子模块

- common
  - service_base: 工具类
  - spring_security: 权限配置
- infrastructure
  - api_getway: 网关
- service
  - service_acl 权限管理模块

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\项目工程结构.png)

启动Redis和Nacos服务

Redis相当于一个数据库  用来存储数据

Nacos 就是一个注册中心

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\Nacos.png)

项目操作步骤

- 编写service_base里面的工具类的内容
- 编写spring_security认证授权的工具类

**DefaultPasswordEncoder 密码处理**

```java
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
```

**TokenLogoutHandle 退出处理器**

```java
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
```

**TokenManager token操作工具类**

```java
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

```

**UnauthorizedEntryPoint  未授权统一处理**

```java
//未授权统一处理类
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        ResponseUtil.out(response, R.error());
    }
}
```

**TokenLoginFilter认证过滤器**

```java
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
```

**TokenAuthenticationFilter授权过滤器**

```java
//授权过滤
public class TokenAuthenticationFilter extends BasicAuthenticationFilter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint, TokenManager tokenManager, RedisTemplate redisTemplate) {
        super(authenticationManager, authenticationEntryPoint);
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //获取当前认证乘公共用户的授权信息
        //获取当前认证成功用户权限信息
        UsernamePasswordAuthenticationToken authRequest = getAuthentication(request);
        //判断如果有权限信息，放到权限上下文中
        if(authRequest != null) {
            SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
        chain.doFilter(request,response);
    }
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request){
        //从Header中获取Token
        String token = request.getHeader("token");
        if (token!=null){
            //从Token中获取用户名
            String username = tokenManager.getUserInfoFromToken(token);
            //从redis获取对应的权限列表
            List<String> permissionValueList = (List<String>)redisTemplate.opsForValue().get(username);
            Collection<GrantedAuthority> authority = new ArrayList<>();
            for(String permissionValue : permissionValueList) {
                SimpleGrantedAuthority auth = new SimpleGrantedAuthority(permissionValue);
                authority.add(auth);
            }
            return new UsernamePasswordAuthenticationToken(username,token,authority);
        }
        return null;
    }
}
```

**TokenWebSecurityConfig核心配置类**

```java
//核心配置类
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(UserDetailsService userDetailsService, DefaultPasswordEncoder defaultPasswordEncoder,
                                  TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.userDetailsService = userDetailsService;
        this.defaultPasswordEncoder = defaultPasswordEncoder;
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }
    /**
     * 配置设置
     * @param http
     * @throws Exception
     */
    //设置退出的地址和token，redis操作地址
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new UnauthorizedEntryPoint())//没有权限访问
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout")//退出路径
                .addLogoutHandler(new TokenLogoutHandle(tokenManager,redisTemplate)).and()
                .addFilter(new TokenLoginFilter( tokenManager, redisTemplate,authenticationManager()))
                .addFilter(new TokenAuthenticationFilter(authenticationManager(),tokenManager, redisTemplate)).httpBasic();
    }

    //调用userDetailsService和密码处理
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }
    //不进行认证的路径，可以直接访问
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}
```

编写UserDetailServiceImpl

```java
@Service("userDetailsService")  这个名字要与配合类里面定义的名字一致
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Autowired
    private PermissionService permissionService;  关于权限的

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查询数据
        User user = userService.selectByUsername(username);
        //判断
        if(user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        User curUser = new User();
        
        BeanUtils.copyProperties(user,curUser);

        //根据用户查询用户权限列表
        List<String> permissionValueList = permissionService.selectPermissionValueByUserId(user.getId());
        SecurityUser securityUser = new SecurityUser();
        securityUser.setCurrentUserInfo(curUser);
        securityUser.setPermissionValueList(permissionValueList);
        return securityUser;
    }
}
```

整体流程是

先进行认证: attemptAuthentication-->成功successfulAuthentication/失败unsuccessfulAuthentication-->在进行授权doFilterInternal

![](C:\Users\Administrator\Desktop\一周\SpringSecurity图片\认证流程详解.png)

**自我理解**

在将前台的登录界面设置为不拦截的请求   前台界面登录执行登录请求之后  就会与Security的核心配置类里面设置的登录路径包含登录方法相匹配  如果匹配合格就会进行认证和授权的检测 检测是否能够进行登录并对其进行授权

其他具体相关代码在这里不在讲述  想要了解的查看我的项目地址



