package com.example.demo.service;

import com.example.demo.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple in-memory refresh token store with rotation.
 * In production use a persistent store (DB or Redis).
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final Map<String, RefreshEntry> store = new ConcurrentHashMap<>();
    private final JwtUtil jwtUtil;

    // create refresh token for subject, returns refresh id
    public String createRefreshToken(String subject) {
        String id = UUID.randomUUID().toString();
        RefreshEntry e = new RefreshEntry(id, subject, Instant.now().plusSeconds(30L * 24 * 60 * 60)); // 30 days
        store.put(id, e);
        return id;
    }

    // rotate refresh token: validate existing id, issue new id, return new pair DTO
    public Optional<RotatedResult> rotateRefreshToken(String existingId) {
        var entry = store.get(existingId);
        if (entry == null) return Optional.empty();
        if (entry.expiry.isBefore(Instant.now())) {
            store.remove(existingId);
            return Optional.empty();
        }
        // remove old, create new
        store.remove(existingId);
        String newId = UUID.randomUUID().toString();
        RefreshEntry newEntry = new RefreshEntry(newId, entry.subject, Instant.now().plusSeconds(30L * 24 * 60 * 60));
        store.put(newId, newEntry);
        // issue a jwt for subject
        return Optional.of(new RotatedResult(newId, entry.subject));
    }

    // revocation
    public void revoke(String id) {
        store.remove(id);
    }

    // issue JWT for subject (simple wrapper)
    public String issueJwtForSubject(String subject) {
        // minimal claims; in real use you would fetch groups and claims
        var claims = Map.<String,Object>of("sub", subject);
        return jwtUtil.generateToken(subject, claims);
    }

    public record RotatedResult(String refreshId, String subject) {}
    private record RefreshEntry(String id, String subject, Instant expiry) {}
}
