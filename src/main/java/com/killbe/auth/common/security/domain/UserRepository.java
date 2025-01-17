package com.killbe.auth.common.security.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(final String username);

    User findByUsernameAndPassword(final String username, final String password);

}
