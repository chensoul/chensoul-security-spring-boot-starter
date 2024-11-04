package com.chensoul.security.jwt;

import com.chensoul.security.util.SecurityUser;
import com.chensoul.security.jwt.token.JwtAuthenticationToken;
import com.chensoul.security.jwt.token.JwtToken;
import com.chensoul.security.jwt.token.JwtTokenFactory;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtTokenFactory tokenFactory;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtToken accessToken = (JwtToken) authentication.getCredentials();
        SecurityUser securityUser = authenticate(accessToken.getToken());
        return new JwtAuthenticationToken(securityUser);
    }

    public SecurityUser authenticate(String accessToken) throws AuthenticationException {
        if (StringUtils.isEmpty(accessToken)) {
            throw new BadCredentialsException("Token is invalid");
        }
        return tokenFactory.parseAccessJwtToken(accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
