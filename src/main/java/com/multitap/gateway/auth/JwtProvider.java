package com.multitap.gateway.auth;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Objects;

@RequiredArgsConstructor
@Slf4j
@Service
public class JwtProvider {

    private final Environment env;

    /**
     * 토큰 검증
     *
     * @param token jwtToken
     * @return true(유효) / false(X)
     */
    public boolean validateToken(String token) {
        try {
            // 토큰 파싱
            log.info("토큰검증");
            Jwts
                    .parser()
                    .verifyWith((SecretKey) getSignKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return true;
        } catch (ExpiredJwtException e) {
            log.info("토큰검증 실패 : 토큰 만료");
            return false;
        } catch (Exception e) {
            log.info("토큰검증 실패 : 토큰 오류");
            return false;
        }
    }

    public Key getSignKey() {
        return Keys.hmacShaKeyFor(Objects.requireNonNull(env.getProperty("jwt.secret")).getBytes());
    }


}
