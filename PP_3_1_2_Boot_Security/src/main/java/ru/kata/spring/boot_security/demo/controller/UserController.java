package ru.kata.spring.boot_security.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping("/user")
public class UserController {

    @GetMapping
    public String userPage(Principal principal, Model model) {
        User user = userService.findUserByUserName(principal.getName());
        model.addAttribute("user", user);
        return "user"; // html
    }
}
