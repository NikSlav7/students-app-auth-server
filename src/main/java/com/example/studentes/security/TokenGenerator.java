package com.example.studentes.security;


import com.example.studentes.domains.Account;
import com.nimbusds.jwt.JWTClaimsSet;
import org.hibernate.query.sqm.TemporalUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
public class TokenGenerator {

    @Autowired
    private  JwtEncoder accessTokenEncoder;

    @Autowired
    @Qualifier("refreshKeyEncoder")
    private  JwtEncoder refreshTokenEncoder;


    private String generateAccessToken(Authentication authentication){
        Account account = (Account) authentication.getPrincipal();
        Instant now = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("students app")
                .issuedAt(now)
                .expiresAt(now.plus(5, ChronoUnit.HOURS))
                .subject(account.getId())
                .build();

        return accessTokenEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }
    private String generateRefreshToken(Authentication authentication){
        Account account = (Account) authentication.getPrincipal();
        Instant now = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuer("students app")
                .issuedAt(now)
                .expiresAt(now.plus(5, ChronoUnit.DAYS))
                .subject(account.getId())
                .build();

        return refreshTokenEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
    }
    public TokenDTO createTokens(Authentication authentication){

        if (!(authentication.getPrincipal() instanceof Account account)) throw new BadCredentialsException("Bad Credentials");

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken(generateAccessToken(authentication));
        tokenDTO.setId(account.getId());


        String refreshToken;

        if (authentication.getCredentials() instanceof Jwt jwt){
            Instant now = Instant.now();
            Instant expires = jwt.getExpiresAt();
            long dur = Duration.between(now, expires).toDays();
            if (dur > 7){
                tokenDTO.setRefreshToken(jwt.getTokenValue());
            }
            else tokenDTO.setRefreshToken(generateRefreshToken(authentication));
        }
        else {
            tokenDTO.setRefreshToken(generateRefreshToken(authentication));
        }
        return tokenDTO;
    }
}
