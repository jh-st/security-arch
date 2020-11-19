package com.killbe.auth.common.security.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserVO {

    private Long id;
    private String userId;
    private char[] userPwd;
    private UserRole role;

}
