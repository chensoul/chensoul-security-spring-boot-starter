package com.chensoul.springboot.security.jwt;

import static java.util.Arrays.asList;
import java.util.List;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.jwt")
@Setter
@Getter
@Validated
public class JwtProperties {
    private static final Long DEFAULT_JWT_TOKEN_EXPIRES = 604800L;
    private static final String DEFAULT_BASE_PATH = "/api/**";
    private static final String DEFAULT_AUTH_TOKEN_PATH = "/api/auth/login";
    private static final String DEFAULT_REFRESH_TOKEN_PATH = "/api/auth/refresh";
    private static final String DEFAULT_AUTH_ME_PATH = "/api/auth/me";

    @NotBlank(message = "issuer can not be empty")
    private String issuer = "";

    @NotBlank(message = "header can not be empty")
    private String header = "Authorization";

    @NotNull(message = "expiresIn can not be empty")
    @Positive(message = "Expiry time can not be less than 1")
    private Long expiresIn = DEFAULT_JWT_TOKEN_EXPIRES;

    @NotBlank(message = "secret can not be empty")
    private String secret;

    @NotBlank(message = "basePath can not be empty")
    private String basePath = DEFAULT_BASE_PATH;

    private List<String> permitAllPaths = asList(
            DEFAULT_AUTH_TOKEN_PATH,
            DEFAULT_REFRESH_TOKEN_PATH
    );
    private boolean enabled = true;
    private String createAuthTokenPath = DEFAULT_AUTH_TOKEN_PATH;
    private String refreshAuthTokenPath = DEFAULT_REFRESH_TOKEN_PATH;
    private String authMePath = DEFAULT_AUTH_ME_PATH;
}
