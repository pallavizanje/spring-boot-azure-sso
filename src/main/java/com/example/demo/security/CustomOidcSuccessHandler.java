package com.example.demo.security;

import com.example.demo.service.GraphService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class CustomOidcSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final GraphService graphService;
    private final RefreshTokenService refreshTokenService;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    private static final String COOKIE_NAME = "SESSION-JWT";
    private static final String REFRESH_COOKIE = "REFRESH-TOKEN";
    private static final int COOKIE_MAX_AGE_SECONDS = 60 * 60; // 1 hour

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser)) {
            response.sendRedirect(frontendUrl);
            return;
        }

        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

        Map<String, Object> claims = new HashMap<>();
        Optional.ofNullable(oidcUser.getClaimAsString("preferred_username")).ifPresent(v -> claims.put("upn", v));
        Optional.ofNullable(oidcUser.getClaimAsString("email")).ifPresent(v -> claims.put("email", v));
        Optional.ofNullable(oidcUser.getFullName()).ifPresent(v -> claims.put("name", v));

        // Try to read groups from ID token claims
        List<String> groups = null;
        Object groupsObj = oidcUser.getClaims().get("groups");
        if (groupsObj instanceof List) {
            groups = new ArrayList<>();
            for (Object o : (List<?>) groupsObj) {
                groups.add(String.valueOf(o));
            }
        }

        // If groups not in token, try to call Graph using the authorized client
        if ((groups == null || groups.isEmpty()) && authentication.getName() != null) {
            OAuth2AuthorizedClient authorizedClient =
                    authorizedClientService.loadAuthorizedClient("azure", authentication.getName());
            if (authorizedClient != null) {
                try {
                    List<String> graphGroups = graphService.getUserGroups(authorizedClient);
                    if (graphGroups != null && !graphGroups.isEmpty()) {
                        groups = graphGroups;
                    }
                } catch (Exception ex) {
                    // ignore
                }
            }
        }

        if (groups != null && !groups.isEmpty()) {
            claims.put("groups", groups);
        }

        String subject = oidcUser.getSubject();
        String token = jwtUtil.generateToken(subject, claims);

        // set JWT cookie
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(false); // set to true in prod, HTTPS required
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        response.addCookie(cookie);

        // generate refresh token, store server-side, set cookie
        String refreshId = refreshTokenService.createRefreshToken(subject);
        Cookie refreshCookie = new Cookie(REFRESH_COOKIE, refreshId);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        refreshCookie.setSecure(false);
        refreshCookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
        response.addCookie(refreshCookie);

        response.sendRedirect(frontendUrl + "/?login=success");
    }
}
