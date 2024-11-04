package com.chensoul.security.jwt.token;

public final class AccessJwtToken implements JwtToken {
	private final String token;

	public AccessJwtToken(String token) {
		this.token = token;
	}

	public String getToken() {
		return this.token;
	}

}
