package com.chensoul.demo;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    private static Map<String, String> credentials = new HashMap<>();

    static {
        credentials.put("admin", "{noop}admin");
        credentials.put("user", "{noop}user");
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (credentials.containsKey(username)) {
            return new User(username, credentials.get(username),
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        }
        throw new UsernameNotFoundException("No user found with username " + username);
    }
}
