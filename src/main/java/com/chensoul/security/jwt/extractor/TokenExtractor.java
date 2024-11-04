package com.chensoul.security.jwt.extractor;

import javax.servlet.http.HttpServletRequest;

public interface TokenExtractor {
    String JWT_TOKEN_HEADER_PARAM = "Authorization";

    String extract(HttpServletRequest request);
}
