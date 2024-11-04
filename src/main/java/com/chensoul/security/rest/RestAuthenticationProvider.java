package com.chensoul.security.rest;

import com.chensoul.security.JwtProperties;
import com.chensoul.security.JwtSecurityConfig;
import com.chensoul.security.jwt.token.TwoFaAuthenticationToken;
import com.chensoul.security.util.SecurityUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

@Slf4j
@RequiredArgsConstructor
public class RestAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder encoder;
    private final JwtProperties jwtProperties;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, "No authentication data provided");

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        SecurityUser securityUser = authenticateByUsernameAndPassword(authentication, username, password);

        if (jwtProperties.getMfa().isEnabled()) {
            return new TwoFaAuthenticationToken(securityUser);
        }

        return new UsernamePasswordAuthenticationToken(securityUser, null, securityUser.getAuthorities());
    }

    private SecurityUser authenticateByUsernameAndPassword(Authentication authentication, String username, String password) {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user==null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        if (!encoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Username or password not valid");
        }

        return new SecurityUser(user.getUsername(), user.getPassword(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
