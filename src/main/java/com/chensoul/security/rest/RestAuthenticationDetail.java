package com.chensoul.security.rest;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.Data;

@Data
public class RestAuthenticationDetail implements Serializable {
    private static final List<String> CLIENT_IP_HEADER_NAMES = Arrays.asList("X-Forwarded-For",
            "X-Real-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR");
    private static final String LOCAL_IP4 = "127.0.0.1";
    private static final String LOCAL_IP6 = "0:0:0:0:0:0:0:1";

    private final String serverAddress;
    private final String clientAddress;

    public RestAuthenticationDetail(HttpServletRequest request) {
        this.clientAddress = getClientIP(request);
        this.serverAddress = handleIpv6(request.getLocalAddr());
    }

    private String getClientIP(HttpServletRequest request) {
        String ip = null;
        for (String header : CLIENT_IP_HEADER_NAMES) {
            ip = request.getHeader(header);
            if (ip!=null) {
                break;
            }
        }

        if (ip==null) {
            ip = request.getRemoteAddr();
        }

        ip = ip.split(",")[0];
        return handleIpv6(ip);
    }

    private String handleIpv6(String ip) {
        if (ip.equals(LOCAL_IP6)) {
            return LOCAL_IP4;
        }
        return ip;
    }
}
