# spring-boot-azure-sso (with JWT rotation)

This project implements Azure AD SSO (OIDC) with Spring Boot, issues JWT cookies on successful login,
includes groups into JWT, and supports refresh-token rotation with an in-memory store.

## How it works
- User clicks login -> redirected to Azure AD (/oauth2/authorization/azure)
- On success, backend issues:
  - HttpOnly cookie SESSION-JWT (the JWT used for auth)
  - HttpOnly cookie REFRESH-TOKEN (an opaque refresh identifier)
- Backend is stateless for auth: JwtAuthenticationFilter validates SESSION-JWT on every request.
- If SESSION-JWT expires, frontend calls POST /api/refresh (credentials included) to rotate refresh token and receive a new JWT cookie.

## Run (dev)
1. Update src/main/resources/application-dev.properties with your Azure app values.
2. Set a secure secret in application.properties (app.jwt.secret).
3. Run:
   mvn spring-boot:run

## Notes
- Refresh tokens are stored in-memory (ConcurrentHashMap). Use a persistent store (Redis/DB) in prod.
- Set cookie Secure=true in production and serve over HTTPS.
- Adjust refresh token lifetime and cookie SameSite attributes per your security policy.
