# sso

sso is a reverse proxy requiring you to be signed in via OAuth to access any backend services.

Upon attemping to access a service that you are not authenticated for you are redirected to a auth service to sign in via Google OAuth. If your email is whitelisted you are redirected back and are allowed to access the service