package com.beour.global.security;

import com.beour.global.jwt.CustomLogoutFilter;
import com.beour.global.jwt.JWTFilter;
import com.beour.global.jwt.JWTUtil;
import com.beour.global.jwt.LoginFilter;
import com.beour.token.repository.RefreshTokenRepository;
import com.beour.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final UserRepository userRepository;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager = authenticationManager();

        LoginFilter loginFilter = new LoginFilter(authenticationManager, userRepository, jwtUtil,
            refreshTokenRepository);
        loginFilter.setFilterProcessesUrl("/api/login");

//        http.cors((cors) -> cors
//            .configurationSource(new CorsConfigurationSource() {
//                @Override
//                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
//
//                    CorsConfiguration configuration = new CorsConfiguration();
//
//                    configuration.setAllowedOrigins(
//                        List.of("http://localhost:3000",
//                            "https://localhost:3000",
//                            "http://beour-bucket.s3-website.ap-northeast-2.amazonaws.com",
//                            "https://beour.store",
//                            "https://www.beour.store")
//                    );
//                    configuration.setAllowedMethods(
//                        List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
//                    configuration.setAllowCredentials(true);    //쿠키 헤더 허용
//                    configuration.setAllowedHeaders(Collections.singletonList("*"));
//                    configuration.setMaxAge(3600L); // preflight 결과 캐시
//
//                    configuration.setExposedHeaders(Collections.singletonList("Authorization"));
//
//                    return configuration;
//                }
//            })
//        );
        http.cors((cors) -> cors.configurationSource(corsConfigurationSource));

        http
            .authorizeHttpRequests((auth) -> auth
                    .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                    .requestMatchers("/api/signup/**", "/api/login",
                        "/api/users/find/login-id", "/api/users/reset/password", "/api/token/reissue")
                    .permitAll()
                    .requestMatchers("/api/spaces/reserve/available-times", "/api/spaces/search/**",
                        "/api/spaces/new", "/api/reviews/new", "/api/banners").permitAll()
//                    .requestMatchers("/admin").hasRole("ADMIN")
                    .requestMatchers("/api/spaces/reserve", "/api/reservation/**", "/api/guest/**",
                        "/api/spaces/*/likes", "/api/likes")
                    .hasRole("GUEST")
                    .requestMatchers("/api/spaces", "/api/spaces/my-spaces", "/api/spaces/*",
                        "/api/spaces/*/*",
                        "/api/host/available-times/spaces", "/api/host/available-times/space/*")
                    .hasRole("HOST")
                    .requestMatchers("/api/mypage/**").hasAnyRole("HOST", "GUEST")
                    .requestMatchers("/api/logout", "/api/users", "/api/users/me/**")
                    .hasAnyRole("HOST", "GUEST", "ADMIN")
                    .anyRequest().authenticated()
//                    .anyRequest().permitAll()
            );

        http
            .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class)
            .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshTokenRepository),
                LogoutFilter.class);

        http
            .formLogin((auth) -> auth.disable())
            .csrf((auth) -> auth.disable())
            .httpBasic((auth) -> auth.disable())
            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}