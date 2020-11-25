package com.ljx.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author 李加喜
 * @date 2020/11/24 0024 14:25
 * @Email 1129071273@qq.com
 */

@Controller
@RequestMapping("/test")

public class TestController {
    @GetMapping("/hello")
    @ResponseBody
    public String add(){
        return "Hello Spring Security";
    }
    @GetMapping("/index")
    //@Secured({"ROLE_admin123"})
    //@PreAuthorize("hasAnyAuthority('admin')")
    @ResponseBody
    public String index(){
        return "成功";
    }
}
