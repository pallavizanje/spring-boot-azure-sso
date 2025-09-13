package com.example.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private static final String COOKIE_NAME = "SESSION-JWT";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (COOKIE_NAME.equals(c.getName())) {
                    token = c.getValue();
                    break;
                }
            }
        }

        if (token != null) {
            try {
                Jws<Claims> jws = jwtUtil.parseToken(token);
                Claims claims = jws.getBody();
                String subject = claims.getSubject();
                String email = claims.get("email", String.class);
                String name = claims.get("name", String.class);

                // map groups claim into authorities
                List<String> groups = new ArrayList<>();
                Object groupsObj = claims.get("groups");
                if (groupsObj instanceof List) {
                    for (Object o : (List<?>) groupsObj) {
                        groups.add(String.valueOf(o));
                    }
                } else if (groupsObj instanceof String) {
                    groups.add((String) groupsObj);
                }

                List<SimpleGrantedAuthority> authorities;
                if (!groups.isEmpty()) {
                    authorities = groups.stream()
                            .map(this::toRoleFromGroup)
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                } else {
                    authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
                }

                Authentication auth = new UsernamePasswordAuthenticationToken(subject, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);

                request.setAttribute("jwtEmail", email);
                request.setAttribute("jwtName", name);

            } catch (Exception e) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    private String toRoleFromGroup(String group) {
        String cleaned = group == null ? "UNKNOWN" : group.replaceAll("[^A-Za-z0-9_\\- ]", "").trim();
        cleaned = cleaned.replaceAll("\\s+", "_").toUpperCase();
        if (cleaned.length() == 0) cleaned = "UNKNOWN";
        return "ROLE_" + cleaned;
    }
}
