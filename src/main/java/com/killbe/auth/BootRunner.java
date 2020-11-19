package com.killbe.auth;

import com.killbe.auth.common.security.domain.User;
import com.killbe.auth.common.security.domain.UserRole;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.persistence.EntityManager;
import javax.transaction.Transactional;

@Slf4j
@Component
public class BootRunner implements ApplicationRunner {

    @Autowired
    EntityManager em;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void run(ApplicationArguments args) throws Exception {
        log.info("SecurityRunner.run");
        char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        String encodePassword = passwordEncoder.encode(String.valueOf(password));

        User user = User.builder()
                .username("test")
                .password(encodePassword.toCharArray())
                .role(UserRole.ROLE_ADMIN)
                .nickname("nickname's")
                .build();

        em.persist(user);
        em.flush();
        em.clear();
    }
}
