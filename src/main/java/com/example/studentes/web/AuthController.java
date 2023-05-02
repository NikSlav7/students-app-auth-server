package com.example.studentes.web;


import com.example.studentes.domains.Account;
import com.example.studentes.domains.AccountsManager;
import com.example.studentes.request.ChangePasswordRequest;
import com.example.studentes.security.TokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;


@Service
@RestController
@RequestMapping("/api/auth")
public class AuthController{

    private final AccountsManager accountsManager;

    private final TokenGenerator tokenGenerator;

    private final DaoAuthenticationProvider daoAuthenticationProvider;

    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private final JwtAuthenticationProvider jwtAccessAuthenticationProvider;

    @Autowired
    public AuthController(AccountsManager accountsManager, TokenGenerator tokenGenerator,
                          DaoAuthenticationProvider daoAuthenticationProvider,
                          @Qualifier("jwtAuthProvider") JwtAuthenticationProvider jwtAuthenticationProvider, JwtAuthenticationProvider jwtAccessAuthenticationProvider) {
        this.accountsManager = accountsManager;
        this.tokenGenerator = tokenGenerator;
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.jwtAccessAuthenticationProvider = jwtAccessAuthenticationProvider;
    }

    @PostMapping("/checktoken")
    public ResponseEntity checkToken(@RequestHeader("Access-Token") String accessToken){
        Authentication authentication = jwtAccessAuthenticationProvider.authenticate(new BearerTokenAuthenticationToken(accessToken));
        if (!authentication.isAuthenticated()) throw new BadCredentialsException("The renew token is not valid");
        return ResponseEntity.ok(authentication.getPrincipal());
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegistrationDTO registrationDTO){
        Account account = new Account(registrationDTO.getUsername(), registrationDTO.getPassword()).activateProfile();
        accountsManager.createUser(account);
        Authentication authentication = new UsernamePasswordAuthenticationToken(account, registrationDTO.getPassword(), Collections.EMPTY_LIST);
        return ResponseEntity.ok(tokenGenerator.createTokens(authentication));
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDTO loginDTO){
        Authentication authentication = daoAuthenticationProvider
                .authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword(), Collections.EMPTY_LIST));
        if (!authentication.isAuthenticated()) throw new BadCredentialsException("The credentials are wrong");
        return ResponseEntity.ok(tokenGenerator.createTokens(authentication));
    }
    @PostMapping("/renew")
    public ResponseEntity token(@RequestBody RenewTokenDTO renewTokenDTO){
        Authentication authentication = jwtAuthenticationProvider.authenticate(new BearerTokenAuthenticationToken(renewTokenDTO.getRefreshToken()));
        if (!authentication.isAuthenticated()) throw new BadCredentialsException("The renew token is not valid");
        return ResponseEntity.ok(tokenGenerator.createTokens(authentication));
    }

    @PostMapping("/change-password")
    public ResponseEntity changePassword(@RequestBody ChangePasswordRequest changePasswordRequest){
        accountsManager.changeAccountPassword(changePasswordRequest.getUsername(), changePasswordRequest.getNewPassword());
        return ResponseEntity.ok(true);
    }





}
