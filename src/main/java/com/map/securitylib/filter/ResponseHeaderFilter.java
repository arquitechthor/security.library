package com.map.securitylib.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ResponseHeaderFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Strict-Transport-Security","max-age=31536000 ; includeSubDomains");
        httpServletResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpServletResponse.setHeader("X-Frame-Options", "DENY");
        httpServletResponse.setHeader("X-XSS-Protection", "1; mode=block");
        httpServletResponse.setHeader("Content-Security-Policy", "default-src 'self' ;img-src data: https:;object-src 'none'; script-src https://stackpath.bootstrapcdn.com/ 'self' 'unsafe-inline';style-src https://stackpath.bootstrapcdn.com/ 'self' 'unsafe-inline'; upgrade-insecure-requests;");
        chain.doFilter(request, response);
    }
}
