package com.example.studentes.exception;


import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ApiExceptionHandler {


    @ExceptionHandler(value = {UsernameNotFoundException.class})
    public ResponseEntity handleException(Exception exception){
        return new ResponseEntity((Object) exception, HttpStatusCode.valueOf(400));
    }
}
