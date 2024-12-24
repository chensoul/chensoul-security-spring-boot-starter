package com.chensoul.security.rest;

import com.chensoul.security.config.JwtProperties;
import com.chensoul.security.jwt.token.JwtPair;
import com.chensoul.security.jwt.token.JwtTokenFactory;
import com.chensoul.security.mfa.MfaAuthenticationToken;
import com.chensoul.security.rest.model.Authority;
import com.chensoul.security.util.SecurityUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@RequiredArgsConstructor
public class RestAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtTokenFactory tokenFactory;
    private final ObjectMapper objectMapper;
    private final JwtProperties jwtProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        JwtPair tokenPair;
        if (authentication instanceof MfaAuthenticationToken) {
            long preVerificationTokenLifetime = jwtProperties.getMfa().getTotalAllowedTimeForVerification();
            tokenPair = new JwtPair();
            tokenPair.setAccessToken(tokenFactory.createPreVerificationToken(securityUser, preVerificationTokenLifetime).getToken());
            tokenPair.setAuthorities(AuthorityUtils.createAuthorityList(Authority.PRE_VERIFICATION_TOKEN.name()));
        } else {
            tokenPair = tokenFactory.createTokenPair(securityUser);
        }

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), tokenPair);

        clearAuthenticationAttributes(request);
    }

    protected final void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session==null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
