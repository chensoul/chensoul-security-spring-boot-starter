package com.chensoul.security.jwt.token;


import com.chensoul.security.util.SecurityUser;

public class RefreshAuthenticationToken extends AbstractJwtAuthenticationToken {

    private static final long serialVersionUID = -1311042791508924523L;

    public RefreshAuthenticationToken(JwtToken jwtToken) {
        super(jwtToken);
    }

    public RefreshAuthenticationToken(SecurityUser securityUser) {
        super(securityUser);
    }
}
