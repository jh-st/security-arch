package com.killbe.auth.common.security.config;

import com.killbe.auth.common.security.filter.StatelessCSRFFilter;
import com.killbe.auth.common.security.handler.CustomAuthenticationProvider;
import com.killbe.auth.common.security.filter.CustomAuthenticationFilter;
import com.killbe.auth.common.security.handler.CustomLoginFailureHandler;
import com.killbe.auth.common.security.handler.CustomLoginSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) {
        log.info("SecurityConfig.configure");
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                // /about 요청에 대해서는 로그인을 요구함
                .antMatchers("/about").authenticated()
                // /admin 요청에 대해서는 ROLE_ADMIN 역할을 가지고 있어야 함
                .antMatchers("/admin").hasRole(UserRole.ROLE_ADMIN.name())
                // 나머지 요청에 대해서는 로그인을 요구하지 않음
                .anyRequest().permitAll()
                .and()
                // 로그인하는 경우에 대해 설정함
                .formLogin()
                // 로그인 페이지를 제공하는 URL을 설정함
                .loginPage("/user/loginView")
                // 로그인 성공 URL을 설정함
                .successForwardUrl("/index")
                // 로그인 실패 URL을 설정함
                .failureForwardUrl("/index")
                .permitAll()
                .and()
                .addFilterBefore(
                        customAuthenticationFilter()
                        , UsernamePasswordAuthenticationFilter.class);
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("SecurityConfig.configure");
        http.formLogin().disable() // 토큰 활용 시 form 기반 로그인 비활성화
            .csrf().disable() // csrf 토큰 비활성화
            // .addFilterBefore(new StatelessCSRFFilter(), CsrfFilter.class) // 커스텀 csrf filter 생성
            .authorizeRequests()
            .anyRequest().permitAll()
            .and()
                // 토큰 활용 시 세션이 필요없음.
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .addFilterBefore(
                        customAuthenticationFilter()
                        , UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        log.info("SecurityConfig.bCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        log.info("SecurityConfig.customAuthenticationFilter");
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        customAuthenticationFilter.setFilterProcessesUrl("/user/login");
        customAuthenticationFilter.setAuthenticationSuccessHandler(customLoginSuccessHandler());
        customAuthenticationFilter.setAuthenticationFailureHandler(customLoginFailureHandler());
        customAuthenticationFilter.afterPropertiesSet();
        return customAuthenticationFilter;
    }

    @Bean
    public CustomLoginFailureHandler customLoginFailureHandler() {
        log.info("SecurityConfig.customLoginFailureHandler");
        return new CustomLoginFailureHandler();
    }

    @Bean
    public CustomLoginSuccessHandler customLoginSuccessHandler() {
        log.info("SecurityConfig.customLoginSuccessHandler");
        return new CustomLoginSuccessHandler();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        log.info("SecurityConfig.customAuthenticationProvider");
        return new CustomAuthenticationProvider(bCryptPasswordEncoder());
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) {
        log.info("SecurityConfig.configure");
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider());
    }
}
