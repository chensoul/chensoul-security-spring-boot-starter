package com.chensoul.security.jwt.token;

import com.chensoul.security.util.SecurityUser;

public class JwtAuthenticationToken extends AbstractJwtAuthenticationToken {

    private static final long serialVersionUID = -8487219769037942225L;

    public JwtAuthenticationToken(JwtToken jwtToken) {
        super(jwtToken);
    }

    public JwtAuthenticationToken(SecurityUser securityUser) {
        super(securityUser);
    }
}
