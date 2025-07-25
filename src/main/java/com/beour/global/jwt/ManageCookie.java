package com.beour.global.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public class ManageCookie {
//    public static Cookie createCookie(String key, String value) {
//        Cookie cookie = new Cookie(key, value);
//        cookie.setMaxAge(24 * 60 * 60); //refresh와 값 같게
//        //todo : 운영 배포시에 아래 주석 활성화
//        //cookie.setSecure(true);
//        //cookie.setPath("/");
//        cookie.setHttpOnly(true);
//
//        return cookie;
//    }

    public static void addRefreshCookie(HttpServletResponse response, String key, String value,
        boolean isSecure) {
        //refresh와 값 같게
        int maxAge = 24 * 60 * 60;

        StringBuilder cookie = new StringBuilder();
        cookie.append(String.format("%s=%s; ", key, value));
        cookie.append("Path=/; ");
        cookie.append("Max-Age=").append(maxAge).append("; ");
        cookie.append("HttpOnly; ");
        cookie.append("SameSite=None; ");

        if (isSecure) {
            cookie.append("Secure;");
        }

        response.addHeader("Set-Cookie", cookie.toString());
    }


}
