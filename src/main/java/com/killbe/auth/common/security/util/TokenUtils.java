package com.killbe.auth.common.security.util;

import com.killbe.auth.common.security.domain.UserDetailsVO;
import com.killbe.auth.common.security.domain.UserRole;
import io.jsonwebtoken.*;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@UtilityClass
public class TokenUtils {

    private static final String secretKey = "ThisIsA_SecretKeyForJwtExample";

    public static String generateJwtToken(UserDetailsVO vo) {
        log.info("TokenUtils.generateJwtToken");
        JwtBuilder builder = Jwts.builder()
                .setSubject(vo.getUserId())
                .setHeader(createHeader())
                .setClaims(createClaims(vo))
                .setExpiration(createExpireDateForOneYear())
                .signWith(SignatureAlgorithm.HS256, createSigningKey());

        return builder.compact();
    }

    public static boolean isValidToken(String token) {
        log.info("TokenUtils.isValidToken");
        try {
            log.info("token : " + token);
            Claims claims = getClaimsFormToken(token);

            log.info("expireTime :" + claims.getExpiration());
            log.info("id :" + claims.get("id"));
            log.info("name :" + claims.get("name"));
            log.info("role :" + claims.get("role"));
            return true;

        } catch (ExpiredJwtException exception) {
            log.error("Token Expired");
            return false;
        } catch (JwtException exception) {
            log.error("Token Tampered");
            return false;
        } catch (NullPointerException exception) {
            log.error("Token is null");
            return false;
        }
    }

    public static String getTokenFromHeader(String header) {
        log.info("TokenUtils.getTokenFromHeader");
        return header.split(" ")[1];
    }

    private static Date createExpireDateForOneYear() {
        log.info("TokenUtils.createExpireDateForOneYear");
        // 토큰 만료시간은 30일으로 설정
        Calendar c = Calendar.getInstance();
        c.add(Calendar.DATE, 30);
        //c.add(Calendar.SECOND, 30);
        return c.getTime();
    }

    private static Map<String, Object> createHeader() {
        log.info("TokenUtils.createHeader");
        Map<String, Object> header = new HashMap<>();

        header.put("typ", "JWT");
        header.put("alg", "HS256");
        header.put("regDate", System.currentTimeMillis());

        return header;
    }

    private static Map<String, Object> createClaims(UserDetailsVO vo) {
        log.info("TokenUtils.createClaims");
        // 공개 클레임에 사용자의 이름과 이메일을 설정하여 정보를 조회할 수 있다.
        Map<String, Object> claims = new HashMap<>();

        claims.put("id", vo.getUserId());
        claims.put("name", vo.getNickname());
        claims.put("role", vo.getRole());

        return claims;
    }

    private static Key createSigningKey() {
        log.info("TokenUtils.createSigningKey");
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretKey);
        return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    private static Claims getClaimsFormToken(String token) {
        log.info("TokenUtils.getClaimsFormToken");
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(secretKey))
                .parseClaimsJws(token).getBody();
    }

    /*private static String getUserIdFromToken(String token) {
        log.info("TokenUtils.getUserEmailFromToken");
        Claims claims = getClaimsFormToken(token);
        return (String) claims.get("id");
    }

    private static UserRole getRoleFromToken(String token) {
        log.info("TokenUtils.getRoleFromToken");
        Claims claims = getClaimsFormToken(token);
        return (UserRole) claims.get("role");
    }*/

}
