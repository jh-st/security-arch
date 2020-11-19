package com.killbe.auth.common.security.config;

import com.killbe.auth.common.security.filter.CorsFilter;
import com.killbe.auth.common.security.filter.HeaderFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Slf4j
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("WebConfig.addInterceptors");
        // 작성한 인터셉터를 추가한다.
        registry.addInterceptor(jwtTokenInterceptor())
                // 예제의 경우 전체 사용자를 조회하는 /user/findAll 에 대해 토큰 검사를 진행한다.
                .addPathPatterns("/user/findAll");
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> getFilterRegistrationBean() {
        log.info("WebConfig.getFilterRegistrationBean");
        FilterRegistrationBean<CorsFilter> registrationBean = new FilterRegistrationBean<>(createHeaderFilter());
        registrationBean.setOrder(Integer.MIN_VALUE);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }

    @Bean
    public CorsFilter createHeaderFilter() {
        log.info("WebConfig.createHeaderFilter");
        return new CorsFilter();
    }

    @Bean
    public JwtTokenInterceptor jwtTokenInterceptor() {
        log.info("WebConfig.jwtTokenInterceptor");
        return new JwtTokenInterceptor();
    }
}
