package com.mycity.user.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth/user")
public class UserProfileController {

    @GetMapping("/profile")
    public String getUserProfile(@RequestHeader Map<String, String> headers) {
        System.out.println("Incoming Headers: " + headers);

        String email = headers.get("x-user-id"); // Header keys are usually lowercase

        if (email == null) {
            return "Unauthorized: User ID is missing in request headers";
        }
        return "Hi, this is the user dashboard: " + email;
    }
}