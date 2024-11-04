package com.chensoul.security.jwt.token;

import com.chensoul.security.util.SecurityUser;

public class TwoFaAuthenticationToken extends AbstractJwtAuthenticationToken {
    public TwoFaAuthenticationToken(SecurityUser securityUser) {
        super(securityUser);
    }
}
