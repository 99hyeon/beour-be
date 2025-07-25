package com.beour.global.jwt;

import com.beour.global.exception.error.errorcode.UserErrorCode;
import com.beour.global.exception.exceptionType.LoginUserMismatchRole;
import com.beour.global.exception.exceptionType.LoginUserNotFoundException;
import com.beour.token.entity.RefreshToken;
import com.beour.token.repository.RefreshTokenRepository;
import com.beour.user.dto.CustomUserDetails;
import com.beour.user.dto.LoginDto;
import com.beour.user.entity.User;
import com.beour.user.enums.TokenExpireTime;
import com.beour.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return null; // 또는 그냥 return
        }

        try {
            LoginDto loginDto = new ObjectMapper().readValue(request.getInputStream(),
                LoginDto.class);
            validateUser(loginDto);

            return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginDto.getLoginId(), loginDto.getPassword(), null)
            );

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void validateUser(LoginDto loginDto) {
        User user = userRepository.findByLoginId(loginDto.getLoginId()).orElse(null);
        if (user == null || user.isDeleted()) {
            throw new LoginUserNotFoundException(UserErrorCode.USER_NOT_FOUND);
        }

        if (!user.getRole().equals(loginDto.getRole())) {
            throw new LoginUserMismatchRole(UserErrorCode.USER_ROLE_MISMATCH);
        }
    }


    //로그인 성공시 수행되는 함수
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain, Authentication authentication)
        throws IOException {

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        //토큰에 넣을 정보(역할, 로그인 아이디) 뽑아옴
        String loginId = customUserDetails.getUsername();
        String role = extractRole(authentication);

        //토큰 생성
        String access = "Bearer " + jwtUtil.createJwt("access", loginId, "ROLE_" + role,
            TokenExpireTime.ACCESS_TOKEN_EXPIRATION_MILLIS.getValue());
        String refresh = jwtUtil.createJwt("refresh", loginId, "ROLE_" + role,
            TokenExpireTime.REFRESH_TOKEN_EXPIRATION_MILLIS.getValue());

        //access는 헤더 refresh는 쿠키에 넣어 보냄
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Authorization", access);
//      response.addCookie(ManageCookie.createCookie("refresh", refresh));

        boolean isSecure = request.isSecure();
        ManageCookie.addRefreshCookie(response, "refresh", refresh, isSecure);

        Map<String, Object> body = Map.of(
            "code", 200,
            "message", "로그인 성공",
            "role", role,
            "accessToken", access
        );

        writeJsonResponse(response, body);

        addRefreshEntity(loginId, refresh,
            TokenExpireTime.REFRESH_TOKEN_EXPIRATION_MILLIS.getValue());
    }

    private static String extractRole(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        return auth.getAuthority();
    }

    private void addRefreshEntity(String loginId, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshToken refreshToken = RefreshToken.builder()
            .loginId(loginId)
            .refresh(refresh)
            .expiration(date.toString())
            .build();

        refreshTokenRepository.save(refreshToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, AuthenticationException failed)
        throws IOException {

        int code;
        String codeName;
        String message;
        if (failed instanceof LoginUserNotFoundException) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            code = ((LoginUserNotFoundException) failed).getErrorCode();
            codeName = "USER_NOT_FOUND";
            message = failed.getMessage();
        } else if (failed instanceof LoginUserMismatchRole) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            code = ((LoginUserMismatchRole) failed).getErrorCode();
            codeName = "ROLE_MISMATCH";
            message = failed.getMessage();
        } else if (failed instanceof BadCredentialsException) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            code = 400;
            codeName = "INVALID_INFORMATION";
            message = "아이디 또는 비밀번호가 올바르지 않습니다.";
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            code = 401;
            codeName = "LOGIN_FAILED";
            message = "로그인에 실패했습니다.";
        }

        Map<String, Object> errorBody = Map.of(
            "code", code,
            "codeName", codeName,
            "message", message
        );

        writeJsonResponse(response, errorBody);
    }

    private void writeJsonResponse(HttpServletResponse response, Map<String, Object> body)
        throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
