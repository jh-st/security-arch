package com.killbe.auth.controller;

import com.killbe.auth.common.security.domain.User;
import com.killbe.auth.common.security.domain.UserRepository;
import com.killbe.auth.common.security.domain.UserVO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userService;

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping(value = "/error/unauthorized")
    public ResponseEntity unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @PostMapping(value = "/user/signUp"
            , consumes = {MediaType.APPLICATION_JSON_VALUE}
            , produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity signUp(@RequestBody UserVO userVO) {
        // 사용자의 이메일이 이미 존재하는 경우 예외를 발생시키고, 없을 경우 비밀번호를 암호화한다.
        if (!userService.findByUsername(userVO.getUserId()).isPresent()) {
            userService.save(User.builder()
                    .username(userVO.getUserId())
                    .role(userVO.getRole())
                    .password(passwordEncoder.encode(String.valueOf(userVO.getUserPwd())).toCharArray())
                    .build()
            );
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();

    }

    @GetMapping(value = "/user/findAll")
    public ResponseEntity findAll() {
        return ResponseEntity.ok(userService.findAll());
    }

}
