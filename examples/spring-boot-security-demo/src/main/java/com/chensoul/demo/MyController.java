package com.chensoul.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {

    @GetMapping("/api/health")
    public String apiHealth() {
        return "UP";
    }

    @GetMapping("/public/hello")
    public String hello() {
        return "World";
    }

    @GetMapping("/api/data")
    public String getData() {
        return "Here is the data";
    }
}
