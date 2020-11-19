package com.killbe.auth.common.security.filter;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request
            , HttpServletResponse response) {
        log.info("CustomAuthenticationFilter.attemptAuthentication");
        UsernamePasswordAuthenticationToken authRequest = null;

        try {
            System.out.println("======================================================");
            System.out.println(obtainUsername(request));
            System.out.println(obtainPassword(request));
            System.out.println("======================================================");

            authRequest = new UsernamePasswordAuthenticationToken(
                    obtainUsername(request)
                    , obtainPassword(request));
            setDetails(request, authRequest);

        } catch (AuthenticationException exception) {
            exception.printStackTrace();
        }

        return this.getAuthenticationManager().authenticate(authRequest);
    }

}
