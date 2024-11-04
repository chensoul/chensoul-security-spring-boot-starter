# chensoul-security-spring-boot-starter

This is a SpringBoot starter to provide JWT token based security autoconfiguration.

## Features

- JWT
- MFA

## How to use?

### Add the dependency

**Maven**

```
<dependency>
    <groupId>com.chensoul</groupId>
    <artifactId>chensoul-security-spring-boot-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

**Gradle**

`compile group: 'com.chensoul', name: 'chensoul-security-spring-boot-starter', version: '0.0.1'`

With the starter dependency is added, you need to configure a bean of type
`org.springframework.security.core.userdetails.UserDetailsService`.

### Configuration

The following configuration properties are available to customize the default behaviour.

| Property                                 | Required | Default Value                                                        |
|------------------------------------------|----------|----------------------------------------------------------------------|
| `security.jwt.enabled`                   | no       | `true`                                                               |
| `security.jwt.token-issuer`              | yes      | `chensoul.com`                                                       |
| `security.jwt.token-signing-key`         | yes      | `secret1234567890123456789012345678912345678901234567890123456789`   |
| `security.jwt.access-token-expire-time`  | yes      | `604800`                                                             |
| `security.jwt.refresh-token-expire-time` | yes      | `9000`                                                               |
| `security.jwt.base-path`                 | yes      | `/api/**`                                                            |
| `security.jwt.login-url`                 | no       | `/api/auth/login`                                                    |
| `security.jwt.refresh-token-url`         | no       | `/api/auth/token`                                                    |
| `security.jwt.paths-to-skip`             | no       | `/api/auth/login,/api/auth/token,/api/noauth/**,/actuator/**,/error` |
| `security.jwt.mfa.enabled`               | no       | `false`                                                              |

If `security.jwt.enabled` property is set to true then following REST endpoints will be available:

### 1. Login/Create Auth Token

```
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"username":"admin","password":"admin"}' \
  http://localhost:8080/api/auth/login
```

**Response JSON:**

```
{
    "access_token": "....",
    "expires_in": "..."
}
```

### 2. Refresh Auth Token

```
curl --header "Authorization: Bearer access_token" \
  --request POST \
  http://localhost:8080/api/auth/refresh
```

**Response JSON:**

```
{
    "access_token": "....",
    "expires_in": "..."
}
```

### 3. Get Authenticated User Info

```
curl --header "Content-Type: application/json" \
  --request GET \
  http://localhost:8080/api/auth/me
```

**Response JSON:**

```
{
    "username": "admin",
    "roles": ["ROLE_USER"]
}
```