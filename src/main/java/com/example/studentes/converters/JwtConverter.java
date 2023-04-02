package com.example.studentes.converters;

import com.example.studentes.domains.Account;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;


@Component
public class JwtConverter implements Converter<org.springframework.security.oauth2.jwt.Jwt, UsernamePasswordAuthenticationToken> {
    @Override
    public UsernamePasswordAuthenticationToken convert(org.springframework.security.oauth2.jwt.Jwt source) {
        Account account = new Account();
        account.setId(source.getSubject());
        return new UsernamePasswordAuthenticationToken(account, source, Collections.EMPTY_LIST);
    }
}
