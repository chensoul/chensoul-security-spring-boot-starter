package com.chensoul.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@EnableCaching
@SpringBootApplication
public class SpringBootJwtSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootJwtSecurityDemoApplication.class, args);
    }

}
