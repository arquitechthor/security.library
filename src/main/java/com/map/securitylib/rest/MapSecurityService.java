package com.map.securitylib.rest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MapSecurityService {
    public boolean validateToken(String mapSecurityURL, String token) {
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(mapSecurityURL+"/"+token, String.class);
        return response.getStatusCode().equals(HttpStatus.OK);
    }
}
