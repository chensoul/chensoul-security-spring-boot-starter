package com.chensoul.security.jwt.token;

public interface TokenCacheService {

	boolean isExpired(String username, String sessionId, long issueTime);

}
