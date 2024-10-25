package com.multitap.gateway.common.exception;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum BaseResponseStatus {


    /**
     * 200: api request success
     **/
    SUCCESS(200,"요청에 성공하였습니다."),

    /**
     * 4000 : jwt token
     */
    NO_JWT_TOKEN(4000,"JWT 토큰이 필요합니다."),

    TOKEN_NOT_VALID(4001,"토큰이 유효하지 않습니다."),

    TOKEN_IS_EXPIRED(4002,"토큰이 만료되었습니다");

    private final int code;
    private final String message;


}
