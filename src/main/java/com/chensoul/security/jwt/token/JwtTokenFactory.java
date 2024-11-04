package com.chensoul.security.jwt.token;

import com.chensoul.security.JwtProperties;
import com.chensoul.security.rest.model.Authority;
import com.chensoul.security.util.SecurityUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

@RequiredArgsConstructor
@Slf4j
public class JwtTokenFactory {
    private static final String SCOPES = "scopes";
    private static final String ENABLED = "enabled";
    private static final String SESSION_ID = "sessionId";

    private final JwtProperties jwtProperties;
    private final ObjectProvider<TokenCacheService> tokenCacheService;

    /**
     * Factory method for issuing new JWT Tokens.
     */
    public JwtToken createAccessJwtToken(SecurityUser securityUser) {
        JwtBuilder jwtBuilder = setUpToken(securityUser, securityUser.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList()), jwtProperties.getAccessTokenExpireTime());
        jwtBuilder.claim(ENABLED, securityUser.isEnabled());

        String token = jwtBuilder.compact();
        return new AccessJwtToken(token);
    }

    public SecurityUser parseAccessJwtToken(String token) {
        Jws<Claims> jwsClaims = parseTokenClaims(token);
        Claims claims = jwsClaims.getBody();
        String subject = claims.getSubject();
        List<String> scopes = claims.get(SCOPES, List.class);
        if (scopes==null || scopes.isEmpty()) {
            throw new IllegalArgumentException("JWT Token doesn't have any scopes");
        }

        SecurityUser securityUser = new SecurityUser(subject, token, AuthorityUtils.createAuthorityList(scopes.toArray(new String[0])));
        if (claims.get(SESSION_ID, String.class)!=null) {
            securityUser.setSessionId(claims.get(SESSION_ID, String.class));
        }

        tokenCacheService.ifAvailable(t -> {
            if (t.isExpired(securityUser.getUsername(), securityUser.getSessionId(), claims.getIssuedAt().getTime())) {
                throw new JwtExpiredTokenException("Token has expired");
            }
        });

        return securityUser;
    }

    public JwtToken createRefreshToken(SecurityUser securityUser) {
        String token = setUpToken(securityUser, Collections.singletonList(Authority.REFRESH_TOKEN.name()), jwtProperties.getRefreshTokenExpireTime())
                .id(UUID.randomUUID().toString()).compact();

        return new AccessJwtToken(token);
    }

    public SecurityUser parseRefreshToken(String token) {
        Jws<Claims> jwsClaims = parseTokenClaims(token);
        Claims claims = jwsClaims.getBody();
        String subject = claims.getSubject();
        @SuppressWarnings("unchecked")
        List<String> scopes = claims.get(SCOPES, List.class);
        if (scopes==null || scopes.isEmpty()) {
            throw new IllegalArgumentException("Refresh Token doesn't have any scopes");
        }
        if (!scopes.get(0).equals(Authority.REFRESH_TOKEN.name())) {
            throw new IllegalArgumentException("Invalid Refresh Token scope");
        }
        SecurityUser securityUser = new SecurityUser(subject, token, AuthorityUtils.createAuthorityList(scopes.toArray(new String[0])));
        if (claims.get(SESSION_ID, String.class)!=null) {
            securityUser.setSessionId(claims.get(SESSION_ID, String.class));
        }

        tokenCacheService.ifAvailable(t -> {
            if (t.isExpired(securityUser.getUsername(), securityUser.getSessionId(), claims.getIssuedAt().getTime())) {
                throw new JwtExpiredTokenException("Token has expired");
            }
        });

        return securityUser;
    }

    public JwtToken createPreVerificationToken(SecurityUser user, Long expirationTime) {
        JwtBuilder jwtBuilder = setUpToken(user, Collections.singletonList(Authority.PRE_VERIFICATION_TOKEN.name()), expirationTime);
        return new AccessJwtToken(jwtBuilder.compact());
    }

    private JwtBuilder setUpToken(SecurityUser securityUser, List<String> scopes, long expirationTime) {
        Claims claims = Jwts.claims().setSubject(securityUser.getUsername())
                .add(SCOPES, scopes)
                .add(SESSION_ID, securityUser.getSessionId())
                .build();

        ZonedDateTime currentTime = ZonedDateTime.now();

        return Jwts.builder()
                .setClaims(claims)
                .issuer(jwtProperties.getTokenIssuer())
                .issuedAt(Date.from(currentTime.toInstant()))
                .expiration(Date.from(currentTime.plusSeconds(expirationTime).toInstant()))
                .signWith(SignatureAlgorithm.HS512, jwtProperties.getTokenSigningKey());
    }

    public Jws<Claims> parseTokenClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(jwtProperties.getTokenSigningKey()).build().parseClaimsJws(token);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Token has Invalid", ex);
        } catch (SignatureException | ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException(token, "Token has expired", expiredEx);
        }
    }

    public JwtPair createTokenPair(SecurityUser securityUser) {
        JwtToken accessToken = createAccessJwtToken(securityUser);
        JwtToken refreshToken = createRefreshToken(securityUser);
        return new JwtPair(accessToken.getToken(), refreshToken.getToken(), securityUser.getAuthorities());
    }

}
