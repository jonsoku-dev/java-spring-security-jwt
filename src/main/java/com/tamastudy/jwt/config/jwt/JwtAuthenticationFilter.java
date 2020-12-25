package com.tamastudy.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에 있는 필터
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");
        // 1. username, password 를 받아서

        // 2. 정상인지 로그인 시도를 해봄 authenticationManager 로 로그인 하면 PrincipalDetailsService 가 호출된다.
        //    -> loadUserByUsernames() 함수가 실행됨

        // 3. PrincipalDetails 를 세션에 담는다 -> 권한관리를 하기위해서 세션에 담는 것!

        // 4. JWT token 을 만들어서 응답해준다.
        return super.attemptAuthentication(request, response);
    }
}
