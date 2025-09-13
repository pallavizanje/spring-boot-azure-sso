package com.example.demo.controller;

import com.example.demo.dto.UserProfileDto;
import com.example.demo.service.GraphService;
import com.example.demo.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final GraphService graphService;
    private final RefreshTokenService refreshTokenService;

    @GetMapping("/login")
    public String login() {
        return "Open /oauth2/authorization/azure to login with Azure AD";
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(
            @RegisteredOAuth2AuthorizedClient("azure") OAuth2AuthorizedClient authorizedClient,
            Authentication auth,
            HttpServletRequest request) {

        UserProfileDto profile = graphService.getUserProfile(authorizedClient);
        if (profile == null && auth != null) {
            String email = (String) request.getAttribute("jwtEmail");
            String name = (String) request.getAttribute("jwtName");
            return ResponseEntity.ok(Map.of(
                    "userId", auth.getName(),
                    "name", name,
                    "email", email
            ));
        }
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/myGroups")
    public List<String> groups(@RegisteredOAuth2AuthorizedClient("azure") OAuth2AuthorizedClient authorizedClient) {
        return graphService.getUserGroups(authorizedClient);
    }

    /**
     * Rotate refresh token and issue new JWT cookie.
     * Frontend should call this endpoint when session JWT is expired.
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(name = "REFRESH-TOKEN", required = false) String refreshId,
                                     HttpServletResponse response) {
        if (refreshId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No refresh token"));
        }
        var result = refreshTokenService.rotateRefreshToken(refreshId);
        if (result.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired refresh token"));
        }
        var dto = result.get();
        // create new JWT for subject
        String subject = dto.getSubject();
        String newJwt = refreshTokenService.issueJwtForSubject(subject);
        // set cookie
        Cookie cookie = new Cookie("SESSION-JWT", newJwt);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(false);
        cookie.setMaxAge(60 * 60);
        response.addCookie(cookie);

        // set new refresh cookie (rotate id returned)
        Cookie refreshCookie = new Cookie("REFRESH-TOKEN", dto.getRefreshId());
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        refreshCookie.setSecure(false);
        refreshCookie.setMaxAge(30 * 24 * 60 * 60);
        response.addCookie(refreshCookie);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "jwtIssuedFor", subject
        ));
    }

    /**
     * Revoke refresh token (logout)
     */
    @PostMapping("/revoke")
    public ResponseEntity<?> revoke(@CookieValue(name = "REFRESH-TOKEN", required = false) String refreshId) {
        if (refreshId != null) {
            refreshTokenService.revoke(refreshId);
        }
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
