package com.map.securitylib.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.map.securitylib.rest.MapSecurityService;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {


    private String internalUrl;

    public CustomAuthorizationFilter(String internalUrl) {
        this.internalUrl = internalUrl;
    }


    @Override
    protected void doFilterInternal(
    		HttpServletRequest request, 
    		HttpServletResponse response, 
    		FilterChain filterChain) throws ServletException, IOException {
    	
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        log.debug("REQUEST PATH: {}",request.getServletPath());
        MapSecurityService mapSecurityService = new MapSecurityService();
        HashMap<String, String> responseMap = new HashMap<>();
        
        if(request.getServletPath().contains("/actuator/health/readiness")
                ||request.getServletPath().contains("/actuator/health/liveness")) {
            filterChain.doFilter(request,response);
        } else {
        	
            //BUSCAMOS EL TOKEN EN EL HEADER
            response.setContentType(APPLICATION_JSON_VALUE);
            log.debug("User token validating...");
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            
            if(authorizationHeader != null && 
            		authorizationHeader.contains("Bearer ")) {
                try {
                    log.debug("Validating token with value: {}", authorizationHeader);
                    String token = authorizationHeader.substring("Bearer ".length());
                    Boolean serviceResponded = mapSecurityService.validateToken(internalUrl, token);

                    if(Boolean.TRUE.equals(serviceResponded)){
                        authorities.add(new SimpleGrantedAuthority("USER"));
                    }
                    
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(token,null,authorities);
                    
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    log.debug("Permitions validation Success!");
                } catch (Exception exception) {
                    log.error("Validation Exception: {}", exception);
                    response.setStatus(FORBIDDEN.value());
                    responseMap.put("statusCode", String.valueOf(FORBIDDEN.value()));
                    responseMap.put("message", FORBIDDEN.name());
                    responseMap.put("error", FORBIDDEN.getReasonPhrase());
                    new ObjectMapper().writeValue(response.getOutputStream(),responseMap);
                }
                filterChain.doFilter(request, response);
            } else {
                log.warn("User not authorized.");
                response.setStatus(UNAUTHORIZED.value());
                responseMap.put("statusCode", String.valueOf(UNAUTHORIZED.value()));
                responseMap.put("message", UNAUTHORIZED.name());
                responseMap.put("error", UNAUTHORIZED.getReasonPhrase());
                new ObjectMapper().writeValue(response.getOutputStream(),responseMap);
                filterChain.doFilter(request, response);
            }
        }
    }
}
