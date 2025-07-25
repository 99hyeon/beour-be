package com.beour.user.service;

import com.beour.global.exception.error.errorcode.UserErrorCode;
import com.beour.global.exception.exceptionType.TokenExpiredException;
import com.beour.global.exception.exceptionType.TokenNotFoundException;
import com.beour.global.exception.exceptionType.UserNotFoundException;
import com.beour.global.jwt.JWTUtil;
import com.beour.token.entity.RefreshToken;
import com.beour.token.repository.RefreshTokenRepository;
import com.beour.user.dto.FindLoginIdRequestDto;
import com.beour.user.dto.FindLoginIdResponseDto;
import com.beour.user.dto.ResetPasswordRequestDto;
import com.beour.user.dto.ResetPasswordResponseDto;
import com.beour.user.entity.User;
import com.beour.user.enums.TokenExpireTime;
import com.beour.user.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class LoginService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public FindLoginIdResponseDto findLoginId(FindLoginIdRequestDto dto) {
        User user = userRepository.findByNameAndPhoneAndEmailAndDeletedAtIsNull(dto.getName(),
            dto.getPhone(),
            dto.getEmail()).orElseThrow(
            () -> new UserNotFoundException(UserErrorCode.MEMBER_NOT_FOUND)
        );

        return new FindLoginIdResponseDto(user.getLoginId());
    }

    @Transactional
    public ResetPasswordResponseDto resetPassword(ResetPasswordRequestDto dto) {
        User user = userRepository.findByLoginIdAndNameAndPhoneAndEmailAndDeletedAtIsNull(
            dto.getLoginId(), dto.getName(),
            dto.getPhone(), dto.getEmail()).orElseThrow(
            () -> new UserNotFoundException(UserErrorCode.MEMBER_NOT_FOUND)
        );

        String tempPassword = generateTempPassword();
        user.updatePassword(bCryptPasswordEncoder.encode(tempPassword));

        return new ResetPasswordResponseDto(tempPassword);
    }

    private String generateTempPassword() {
        int length = 10;
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();

        Random random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }

    public String[] reissueRefreshToken(HttpServletRequest request) {
        String refresh = extractRefreshFromCookie(request);
        checkRefreshTokenIsValid(refresh);

        String loginId = jwtUtil.getLoginId(refresh);
        String role = jwtUtil.getRole(refresh);

        String newAccessToken = "Bearer " + jwtUtil.createJwt("access", loginId, role,
            TokenExpireTime.ACCESS_TOKEN_EXPIRATION_MILLIS.getValue());

        String newRefreshToken = jwtUtil.createJwt("refresh", loginId, role,
            TokenExpireTime.REFRESH_TOKEN_EXPIRATION_MILLIS.getValue());

        refreshTokenRotation(refresh, loginId, newRefreshToken);

        return new String[]{newAccessToken, newRefreshToken};
    }

    private static String extractRefreshFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void checkRefreshTokenIsValid(String refresh) {
        if (refresh == null) {
            throw new TokenNotFoundException(UserErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }

        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException ex) {
            throw new TokenExpiredException(UserErrorCode.REFRESH_TOKEN_EXPIRED);
        }

        if (!"refresh".equals(jwtUtil.getCategory(refresh))
            || !refreshTokenRepository.existsByRefresh(refresh)) {
            throw new TokenNotFoundException(UserErrorCode.REFRESH_TOKEN_NOT_FOUND);
        }
    }

    private void refreshTokenRotation(String refresh, String loginId, String newRefreshToken) {
        refreshTokenRepository.deleteByRefresh(refresh);
        addRefreshToken(loginId, newRefreshToken);
    }

    private void addRefreshToken(String loginId, String newRefreshToken) {
        RefreshToken refreshToken = RefreshToken.builder()
            .loginId(loginId)
            .refresh(newRefreshToken)
            .expiration(new Date(System.currentTimeMillis()
                + TokenExpireTime.REFRESH_TOKEN_EXPIRATION_MILLIS.getValue()).toString())
            .build();

        refreshTokenRepository.save(refreshToken);
    }
}
