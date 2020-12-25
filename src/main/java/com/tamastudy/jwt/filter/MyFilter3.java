package com.tamastudy.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰: tama 이걸 만들어줘야 함. id, pw 가 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들어주고 그걸 응답 해준다.
        // 요청할 때 마다 header 에 Authorization 에 value 값으로 토큰을 가져온다.
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨 (RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청 됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터 1");

            if (headerAuth.equals("tama")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안됨");
            }
        }

        chain.doFilter(req, res);
    }
}
