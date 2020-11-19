package com.killbe.auth.common.security.config;

import com.killbe.auth.common.security.filter.CorsFilter;
import com.killbe.auth.common.security.filter.StatelessCSRFFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfFilter;

import javax.servlet.Filter;

@Slf4j
@Configuration
public class FilterConfig {

    @Bean
    public Filter corsFilter() {
        log.info("FilterConfig.corsFilter");
        return new CorsFilter();
    }

    @Bean
    public Filter csrfFilter() {
        log.info("FilterConfig.csrfFilter");
        return new StatelessCSRFFilter();
    }

}
