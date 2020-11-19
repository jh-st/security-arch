package com.killbe.auth.common.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CorsFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {
        log.info("CorsFilter.doFilterInternal");
        //response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:8080");
        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

        System.out.println("======================================================");
        System.out.println(request.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD));
        System.out.println(request.getMethod());
        System.out.println("======================================================");

        //if (request.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD) != null && HttpMethod
        // .OPTIONS.name().equals(request.getMethod())) {
            // CORS "pre-flight" request
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, PUT, DELETE");
            response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, HttpHeaders.CONTENT_TYPE + ", " + StatelessCSRFFilter.X_CSRF_TOKEN_HEADER);
            response.addHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "1");
        //}

        filterChain.doFilter(request, response);
    }
}
