package com.chensoul.security.config;

import com.chensoul.security.jwt.JwtAuthenticationProvider;
import com.chensoul.security.jwt.RefreshTokenAuthenticationProvider;
import com.chensoul.security.jwt.token.DefaultTokenCacheService;
import com.chensoul.security.jwt.token.JwtTokenFactory;
import com.chensoul.security.jwt.token.TokenCacheService;
import com.chensoul.security.rest.RestAuthenticationFailureHandler;
import com.chensoul.security.rest.RestAuthenticationProvider;
import com.chensoul.security.rest.RestAuthenticationSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final ObjectProvider<TokenCacheService> tokenCacheService;
    private final UserDetailsService userDetailsService;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;

    @Bean
    @ConditionalOnMissingBean
    protected PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(ObjectPostProcessor<Object> objectPostProcessor) throws Exception {
        AuthenticationManagerBuilder auth = new AuthenticationManagerBuilder(objectPostProcessor);
        DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
        auth.authenticationEventPublisher(eventPublisher);

        if (jwtProperties.isEnabled()) {
            auth.authenticationProvider(new RestAuthenticationProvider(userDetailsService, passwordEncoder(), jwtProperties));
            auth.authenticationProvider(new JwtAuthenticationProvider(jwtTokenFactory()));
            auth.authenticationProvider(new RefreshTokenAuthenticationProvider(userDetailsService, jwtTokenFactory()));
        } else {
            auth.authenticationProvider(new DaoAuthenticationProvider());
        }
        return auth.build();
    }

    @Bean
    public JwtTokenFactory jwtTokenFactory() {
        return new JwtTokenFactory(jwtProperties, tokenCacheService);
    }

    @Bean("defaultAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler defaultAuthenticationSuccessHandler() {
        return new RestAuthenticationSuccessHandler(jwtTokenFactory(), objectMapper, jwtProperties);
    }

    @Bean("defaultAuthenticationFailureHandler")
    public AuthenticationFailureHandler defaultAuthenticationFailureHandler() {
        return new RestAuthenticationFailureHandler(objectMapper);
    }

    @Configuration
    @RequiredArgsConstructor
    @ConditionalOnBean(CacheManager.class)
    public class TokenCacheConfig {
        private final CacheManager cacheManager;

        @Bean
        @ConditionalOnMissingBean
        public DefaultTokenCacheService tokenCacheService() {
            return new DefaultTokenCacheService(cacheManager);
        }
    }
}
