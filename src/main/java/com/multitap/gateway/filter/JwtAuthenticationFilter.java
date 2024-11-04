package com.multitap.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.multitap.gateway.auth.JwtProvider;
import com.multitap.gateway.common.ApiResponse;
import com.multitap.gateway.common.exception.BaseResponseStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtProvider jwtProvider;
    private final RedisTemplate<String, String> redisTemplate;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, RedisTemplate<String, String> redisTemplate) {
        super(Config.class);
        this.jwtProvider = jwtProvider;
        this.redisTemplate = redisTemplate;
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authorizationHeader = request.getHeaders().getFirst("Authorization");
            String refreshToken = request.getHeaders().getFirst("Refresh-Token");

            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return handleException(exchange, BaseResponseStatus.NO_JWT_TOKEN);
            }

            String token = authorizationHeader.replace("Bearer ", "");

            // 블랙리스트 체크
            if (isBlacklisted(token)) {
                return handleException(exchange, BaseResponseStatus.TOKEN_NOT_VALID);
            }

            // 액세스 토큰 검증
            if (!jwtProvider.validateToken(token)) {
                // 액세스 토큰이 만료된 경우 리프레시 토큰을 확인
                if (refreshToken == null || !jwtProvider.validateToken(refreshToken)) {
                    return handleException(exchange, BaseResponseStatus.TOKEN_NOT_VALID);
                }

                return handleException(exchange, BaseResponseStatus.ACCESS_TOKEN_EXPIRE);
            }

            return chain.filter(exchange);
        };
    }

    private boolean isBlacklisted(String token) {
        // Redis에서 블랙리스트 체크
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }

    private Mono<Void> handleException(ServerWebExchange exchange, BaseResponseStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ApiResponse<String> apiResponse = new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), status.getCode(), status.getMessage());

        ObjectMapper objectMapper = new ObjectMapper();
        byte[] data;
        try {
            data = objectMapper.writeValueAsBytes(apiResponse);
        } catch (JsonProcessingException e) {
            data = new byte[0];
        }

        DataBuffer buffer = response.bufferFactory().wrap(data);
        return response.writeWith(Mono.just(buffer)).then(Mono.empty());
    }
}
