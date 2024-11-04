package com.chensoul.security.rest.exception;

import org.springframework.security.authentication.AuthenticationServiceException;

public class CredentialsExpiredResponse extends AuthenticationServiceException {

    private final String resetToken;

    protected CredentialsExpiredResponse(String message, String resetToken) {
        super(message);
        this.resetToken = resetToken;
    }

    public static CredentialsExpiredResponse of(final String message, final String resetToken) {
        return new CredentialsExpiredResponse(message, resetToken);
    }

    public String getResetToken() {
        return resetToken;
    }
}
