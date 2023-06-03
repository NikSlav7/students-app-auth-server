package com.example.studentes.security;


import com.example.studentes.converters.JwtConverter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
public class WebConfig {

    @Autowired
    KeyUtils keyUtils;

    private final JwtConverter jwtConverter;

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    @Value("${resource-server.domain}")
    private String RESOURCE_SERVER_DOMAIN;
    @Value("${frontend.domain}")
    private  String FRONTEND_DOMAIN;

    @Value("${dev-resource-server.domain}")
    private String DEV_RESOURCE_SERVER_DOMAIN;
    @Value("${dev-frontend.domain}")
    private  String DEV_FRONTEND_DOMAIN;

    @Autowired
    public WebConfig(JwtConverter jwtConverter, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.jwtConverter = jwtConverter;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/api/auth/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and().csrf().disable().cors().disable()
                .oauth2ResourceServer((oauth2) -> oauth2.jwt().jwtAuthenticationConverter(jwtConverter)).
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().exceptionHandling();
        return http.build();
    }
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins(
                        FRONTEND_DOMAIN, DEV_FRONTEND_DOMAIN, "https://koolitrek.info","http://koolitrek.info" ,"http://localhost:3000", "http://212.224.88.70").allowedMethods("*");
            }
        };
    }


    @Bean
    @Primary
    public JwtDecoder accessKeyJwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getAccessTokenPublicKey()).build();
    }
    @Bean
    @Primary
    public JwtEncoder accessKeyJwtEncoder(){
        JWK jwk = new RSAKey.Builder(keyUtils.getAccessTokenPublicKey()).privateKey(keyUtils.getAccessTokenPrivateKey()).build();
        JWKSource<SecurityContext> source = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(source);
    }

    @Bean
    @Qualifier("refreshKeyDecoder")
    public JwtDecoder refreshKeyJwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(keyUtils.getRefreshTokenPublicKey()).build();
    }
    @Bean
    @Qualifier("refreshKeyEncoder")
    public JwtEncoder refreshKeyJwtEncoder(){
        JWK jwk = new RSAKey.Builder(keyUtils.getRefreshTokenPublicKey()).privateKey(keyUtils.getRefreshTokenPrivateKey()).build();
        JWKSource<SecurityContext> source = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(source);
    }

    @Bean
    @Qualifier("jwtAuthProvider")
    public JwtAuthenticationProvider jwtAuthenticationProvider(){
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(refreshKeyJwtDecoder());
        jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtConverter);
        return jwtAuthenticationProvider;
    }
    @Bean
    @Primary
    public JwtAuthenticationProvider jwtAccessAuthenticationProvider(){
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(accessKeyJwtDecoder());
        jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtConverter);
        return jwtAuthenticationProvider;
    }
    @Bean
    @DependsOn("passwordEncoder")
    DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }


}
