package com.killbe.auth.common.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

@Slf4j
public class StatelessCSRFFilter extends OncePerRequestFilter {

    public static final String X_CSRF_TOKEN_HEADER = "X-CSRF-TOKEN";
    public static final String CSRF_TOKEN_COOKIE = "CSRF-TOKEN";
    private static final int EXPIRE = 0;
    private final RequestMatcher requireCsrfProtectionMatcher = new DefaultRequiresCsrfMatcher();
    private final AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("StatelessCSRFFilter.doFilterInternal");
        if (requireCsrfProtectionMatcher.matches(request)) {
            final String csrfTokenValue = request.getHeader(X_CSRF_TOKEN_HEADER);
            final Cookie[] cookies = request.getCookies();

            String csrfCookieValue = null;
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(CSRF_TOKEN_COOKIE)) {
                        csrfCookieValue = cookie.getValue();
                    }
                }
            }

            if (csrfTokenValue == null || !csrfTokenValue.equals(csrfCookieValue)) {
                accessDeniedHandler.handle(request, response, new AccessDeniedException("Missing or non-matching CSRF-token"));
                log.warn("Missing/bad CSRF-TOKEN while CSRF is enabled for request {}", request.getRequestURI());
                return;
            }
        }

        invalidate(response);
        filterChain.doFilter(request, response);
    }

    private void invalidate(HttpServletResponse response) {
        log.info("StatelessCSRFFilter.invalidate");
        Cookie cookie = new Cookie(CSRF_TOKEN_COOKIE, "");
        cookie.setMaxAge(EXPIRE);
        response.addCookie(cookie);
    }

    private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
        private final Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

        @Override
        public boolean matches(HttpServletRequest request) {
            log.info("DefaultRequiresCsrfMatcher.matches");
            return !allowedMethods.matcher(request.getMethod()).matches();
        }
    }
}
