package com.example.studentes.web;


import com.example.studentes.domains.Account;
import com.example.studentes.domains.AccountsManager;
import com.example.studentes.dto.RegistrationDTO;
import com.example.studentes.dto.RenewTokenDTO;
import com.example.studentes.dto.ValidatePasswordTokenDTO;
import com.example.studentes.exception.ResourceServerError;
import com.example.studentes.request.ChangePasswordRequest;
import com.example.studentes.security.TokenGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;


@Service
@RestController
@RequestMapping("/api/auth")
public class AuthController{

    private final AccountsManager accountsManager;

    private final TokenGenerator tokenGenerator;

    private final DaoAuthenticationProvider daoAuthenticationProvider;

    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private final JwtAuthenticationProvider jwtAccessAuthenticationProvider;


    @Value("${resource-server.domain}")
    private String resourceServerUrl;

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
    public ResponseEntity changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, HttpServletRequest request, @RequestHeader Map<String, String> headers) throws ResourceServerError, IOException {
        validatePasswordToken(changePasswordRequest.getToken(), changePasswordRequest.getUsername());
        accountsManager.changeAccountPassword(changePasswordRequest.getUsername(), changePasswordRequest.getNewPassword());
        return ResponseEntity.ok(true);
    }

    private boolean  validatePasswordToken(String token, String username) throws IOException, ResourceServerError{
        URL url = new URL("http://" + resourceServerUrl + "/api/password-reset/validate");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type","application/json");
        connection.setDoOutput(true);
        String data = new ObjectMapper().writeValueAsString(new ValidatePasswordTokenDTO(username, token));
        try(OutputStream outputStream = connection.getOutputStream()){
            byte[] sendData = data.getBytes(StandardCharsets.UTF_8);
            outputStream.write(sendData, 0, sendData.length);
        } catch (Exception exception){
            exception.printStackTrace();
        }
        if (connection.getResponseCode() != 200) throw new ResourceServerError("Some error occured");
        return true;

    }





}
