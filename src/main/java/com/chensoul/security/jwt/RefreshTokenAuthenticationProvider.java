package com.chensoul.security.jwt;

import com.chensoul.security.util.SecurityUser;
import com.chensoul.security.jwt.token.JwtToken;
import com.chensoul.security.jwt.token.JwtTokenFactory;
import com.chensoul.security.jwt.token.RefreshAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class RefreshTokenAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final JwtTokenFactory tokenFactory;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided");
        JwtToken jwtToken = (JwtToken) authentication.getCredentials();
        SecurityUser unsafeUser = tokenFactory.parseRefreshToken(jwtToken.getToken());
        SecurityUser securityUser = authenticateByUserId(unsafeUser.getUsername());
        securityUser.setSessionId(unsafeUser.getSessionId());

        return new RefreshAuthenticationToken(securityUser);
    }

    private SecurityUser authenticateByUserId(String username) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user==null) {
            throw new UsernameNotFoundException("User not found by refresh token");
        }

        return new SecurityUser(user.getUsername(), user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (RefreshAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
