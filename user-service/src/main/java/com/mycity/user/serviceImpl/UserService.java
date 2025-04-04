package com.mycity.user.serviceImpl;

import java.time.LocalDateTime;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mycity.user.config.JwtService;
import com.mycity.shared.dto.*;
import com.mycity.user.entity.User;
import com.mycity.user.repository.UserRepository;
import com.mycity.user.service.UserServiceInterface;

import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class UserService implements UserServiceInterface {
///	
	private  final UserRepository userRepository;
    private  final PasswordEncoder passwordEncoder; 
    
    private final JwtService jwtservice;

    @Override
    public void registerUser(UserRegRequest request) {
        // Manual validation checks
        if (request.getFirstname() == null || request.getFirstname().trim().isEmpty()) {
            throw new IllegalArgumentException("First name cannot be blank");
        }
        if (request.getLastname() == null || request.getLastname().trim().isEmpty()) {
            throw new IllegalArgumentException("Last name cannot be blank");
        }
        if (request.getEmail() == null || request.getEmail().trim().isEmpty() || !isValidEmail(request.getEmail())) {
            throw new IllegalArgumentException("Invalid email format");
        }
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }

        // Encode the password
        String encodedPassword = passwordEncoder.encode(request.getPassword());

     // Create a new User entity
        User user = new User();
        user.setUsername(request.getFirstname() + " " + request.getLastname()); // Concatenate firstname and lastname with a space
        user.setEmail(request.getEmail());
        user.setPassword(encodedPassword);
        user.setCreatedDate(LocalDateTime.now());
        user.setUpdatedDate(LocalDateTime.now());
        user.setRole("USER");//hardcoded
        
        System.out.println("User registration data is valid. Proceeding with registration...");
        userRepository.save(user);
    }
    
    private boolean isValidEmail(String email) {
        // A more robust email validation using a regular expression is recommended
        return email.contains("@") && email.contains(".");
    }

    @Override
    public String LoginUser(UserLoginRequest request) {
    	String email = request.getEmail();
        String password = request.getPassword();

        // Find the user by email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Validate the password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        System.out.println("Login Successfull");
        // Authentication successful, generate JWT token
        return jwtservice.GenerateToken(user.getId(), user.getEmail(), user.getRole()); // Assuming User entity has getId(), getEmail(), and getRole()
    }
}
