Implementing a basic JWKS Server
Objective
Develop a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

Chooses an appropriate language and web server for the task.

Due to the simplicity of this assignment, I would prefer you complete it with an unfamiliar language… but as I have no way to verify it, it’s not considered part of the rubric.

This project is for educational purposes. In a real-world scenario, you’d want to integrate with a proper authentication system and ensure security best practices.

Background
HTTP/web servicesLinks to an external site.
Familiarize yourself with client/server HTTP services.
RESTLinks to an external site.
Familiarize yourself with correct HTTP methods/headers/status codes for RESTful APIs.
JOSE: JWTLinks to an external site., JWK (and JWKS):Links to an external site.
Familiarize yourself with the concepts of JWT, JWK.
Understand the importance of key expiry, and kid.
Requirements
Key Generation
Implement RSA key pair generation.
Associate a Key ID (kid) and expiry timestamp with each key.
Web server with two handlers
Serve HTTP on port 8080
A RESTful JWKS endpoint that serves the public keys in JWKS format.
Only serve keys that have not expired.
A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.
Documentation
Code should be organized.
Code should be commented where needed.
Code should be linted per your language/framework.
Tests
Test suite for your given language/framework with tests for you.
Test coverage should be over 80%.
Blackbox testing
Ensure the included test clientLinks to an external site. functions against your server.
The testing client will attempt a POST to /auth with no body. There is no need to check authentication for this project.
NOTE: We are not actually testing user authentication, just mocking authentication and returning a valid JWT for this user
Note:
Using kid in JWKS is crucial for systems to identify which key to use for JWT verification. Ensure that the JWTs include the kid in their headers and that the JWKS server can serve the correct key when requested with a specific kid.

Expected Outcome
At the end of the project, you should have a functional JWKS server with a RESTful API that can serve public keys with expiry and unique kid to verify JWTs.

The server should authenticate fake users requests, issue JWTs upon successful authentication, and handle the “expired” query parameter to issue JWTs signed with an expired key.

This project should take 1-12 hours, depending on your familiarity with your chosen language/framework, and web servers in general.

Deliverables
Provide a link to your GitHub repo containing your code.
Include in the repo a screenshot of the test clientLinks to an external site. running against your server.
Include in the repo a screenshot of your test suite (if present) showing the coverage percent.
