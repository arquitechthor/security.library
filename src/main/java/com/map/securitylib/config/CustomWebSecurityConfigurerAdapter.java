package com.map.securitylib.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.map.securitylib.filter.CustomAuthorizationFilter;

@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfigurerAdapter {

    @Value("${map.security.service.url}")
    public String mapSecurityURL;

    @Value("${cors.allowed.origins:*}")
    public String origins;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .formLogin(login -> login.disable())
                .httpBasic(basic -> basic.disable())
                .anonymous(anonymous -> anonymous.disable())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                                .requestMatchers("/actuator/**").permitAll()
                                .requestMatchers("/actuator/health/readiness").permitAll()
                                .requestMatchers("/actuator/health/liveness").permitAll()
                                .requestMatchers("/error").permitAll()
                )
                .authorizeHttpRequests(request -> request
                                .requestMatchers("/**").authenticated()
                )
                .addFilterBefore(new CustomAuthorizationFilter(mapSecurityURL), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
