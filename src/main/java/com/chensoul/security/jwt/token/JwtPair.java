package com.chensoul.security.jwt.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collection;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtPair {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    private Collection<GrantedAuthority> authorities;
}
