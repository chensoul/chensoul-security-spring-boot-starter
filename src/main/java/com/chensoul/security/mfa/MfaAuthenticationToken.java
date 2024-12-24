package com.chensoul.security.mfa;

import com.chensoul.security.jwt.token.AbstractJwtAuthenticationToken;
import com.chensoul.security.util.SecurityUser;

public class MfaAuthenticationToken extends AbstractJwtAuthenticationToken {
    public MfaAuthenticationToken(SecurityUser securityUser) {
        super(securityUser);
    }
}
