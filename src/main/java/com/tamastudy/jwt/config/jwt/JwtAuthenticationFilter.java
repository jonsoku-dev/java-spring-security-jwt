package com.tamastudy.jwt.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tamastudy.jwt.config.auth.PrincipalDetails;
import com.tamastudy.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

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
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            System.out.println("authenticationToken = " + authenticationToken);

            // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 이 리턴됨.
            // DB 에 있는 username 과 password 가 일치한다.
            // 토큰을 넣어서 던져주면 내부 인증로직이 돌아감
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);
            // authentication 객체가 session 영역에 저장해야하고 그 방법이 return 해주는 것
            // 리턴해주는 이유는 권한 관리를 security 가 대신 해주기 때문에 편하려고 하는거임.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없음. 근데 단지 권한 처리 때문에 session 넣어준다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthencation 실핼 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
    // JWT 토큰을 만들어서 request 요청한 사용자들에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행 됨: 인증이 완료되었다는 뜻");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}