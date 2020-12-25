package com.tamastudy.jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "cos"; // 우리 서버만 알고 있는 비밀값
    int EXPIRATION_TIME = 36000; // 60 * 60 * 1000
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
