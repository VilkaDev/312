package ru.kata.spring.boot_security.demo.repository;


import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.demo.model.User;

@Repository
public interface UserRepoImpl extends CrudRepository<User,Long> {
    User findByUsername(String username);
}
