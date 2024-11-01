package com.chensoul.springboot.security.jwt.domain;

import javax.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;


@Setter
@Getter
public class AuthenticationRequest {
    @NotBlank(message = "UserName cannot be blank")
    private String username;

    @NotBlank(message = "Password cannot be blank")
    private String password;
}
