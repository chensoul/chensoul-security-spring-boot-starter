package com.chensoul.security.config;

import com.chensoul.security.jwt.JwtTokenAuthenticationProcessingFilter;
import com.chensoul.security.jwt.RefreshTokenProcessingFilter;
import com.chensoul.security.util.SkipPathRequestMatcher;
import com.chensoul.security.mfa.MfaAuthController;
import com.chensoul.security.rest.RestAccessDeniedHandler;
import com.chensoul.security.rest.RestLoginProcessingFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
@Order(SecurityProperties.BASIC_AUTH_ORDER)
//@AutoConfigureAfter(SecurityProperties.class)
public class JwtSecurityConfig {
    @Qualifier("defaultAuthenticationSuccessHandler")
    private final AuthenticationSuccessHandler defaultAuthenticationSuccessHandler;
    @Qualifier("defaultAuthenticationFailureHandler")
    private final AuthenticationFailureHandler defaultAuthenticationFailureHandler;
    private final AuthenticationManager authenticationManager;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;
//    @Nullable
//    @Qualifier("oauth2AuthenticationSuccessHandler")
//    private ObjectProvider<AuthenticationSuccessHandler> oauth2AuthenticationSuccessHandler;
//    @Nullable
//    @Qualifier("oauth2AuthenticationFailureHandler")
//    private ObjectProvider<AuthenticationFailureHandler> oauth2AuthenticationFailureHandler;

//    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
//    private OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver;
//    OAuth2Configuration oauth2Configuration;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (!jwtProperties.isEnabled()) {
            http.authorizeRequests().antMatchers("/error").permitAll();
            return http.build();
        }
        http.headers(headers -> headers.cacheControl(withDefaults()).frameOptions(withDefaults()).disable())
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(config ->
                        config.antMatchers(jwtProperties.getPathsToSkip().toArray(new String[0])).permitAll() // Protected WebSocket API End-points
                                .antMatchers(jwtProperties.getBaseUrl()).authenticated() // Protected API End-points
                                .anyRequest().permitAll()
                )
                .exceptionHandling(config -> config.accessDeniedHandler(new RestAccessDeniedHandler(objectMapper)))
                .addFilterBefore(refreshTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtTokenAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(refreshTokenProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

//        if (oauth2Configuration!=null) {
//            http.oauth2Login(login -> login
//                    .authorizationEndpoint(config -> config
//                            .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
//                            .authorizationRequestResolver(oAuth2AuthorizationRequestResolver))
//                    .loginPage("/oauth2Login")
//                    .loginProcessingUrl(oauth2Configuration.getLoginProcessingUrl())
//                    .successHandler(oauth2AuthenticationSuccessHandler)
//                    .failureHandler(oauth2AuthenticationFailureHandler));
//        }
        return http.build();
    }

    @ConditionalOnProperty(prefix = "security.jwt.mfa", value = "enabled", havingValue = "true")
    @ComponentScan(basePackageClasses = MfaAuthController.class)
    public class MfaConfig {

    }

    protected RestLoginProcessingFilter restLoginProcessingFilter() {
        RestLoginProcessingFilter filter = new RestLoginProcessingFilter(jwtProperties.getLoginUrl(), objectMapper, defaultAuthenticationSuccessHandler, defaultAuthenticationFailureHandler);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    protected JwtTokenAuthenticationProcessingFilter jwtTokenAuthenticationProcessingFilter() {
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(jwtProperties.getPathsToSkip(), jwtProperties.getBaseUrl());
        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(defaultAuthenticationFailureHandler, matcher);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }

    protected RefreshTokenProcessingFilter refreshTokenProcessingFilter() {
        RefreshTokenProcessingFilter filter = new RefreshTokenProcessingFilter(jwtProperties.getTokenRefreshUrl(), objectMapper, defaultAuthenticationSuccessHandler, defaultAuthenticationFailureHandler);
        filter.setAuthenticationManager(this.authenticationManager);
        return filter;
    }
}
