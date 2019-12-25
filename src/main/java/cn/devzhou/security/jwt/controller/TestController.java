package cn.devzhou.security.jwt.controller;

import cn.devzhou.security.jwt.annotations.Authorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/")
    public String index(){
        return "OK";
    }

    @Authorize
    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }
}
