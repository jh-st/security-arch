package com.killbe.auth.common.security.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CustomLoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request
            , HttpServletResponse response
            , AuthenticationException exception) throws IOException, ServletException {
        log.info("CustomLoginFailureHandler.onAuthenticationFailure");

        System.out.println("exception = " + exception);

        if (exception instanceof BadCredentialsException) {
            log.error("Invalid Username or Password");
        } else if (exception instanceof InsufficientAuthenticationException) {
            log.error("Invalid Secret Key");

            setDefaultFailureUrl("/login?error=true");
            super.onAuthenticationFailure(request, response, exception);
        }
    }


}
