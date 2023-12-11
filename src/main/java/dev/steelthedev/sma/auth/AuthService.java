package dev.steelthedev.sma.auth;

import dev.steelthedev.sma.config.JwtService;
import dev.steelthedev.sma.user.Role;
import dev.steelthedev.sma.user.User;
import dev.steelthedev.sma.user.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.IllegalFormatException;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final  JwtService jwtService;
    public AuthenticationResponse login(LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );
        var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();
        String token = jwtService.generateToken(authentication);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse register(RegisterRequest registerRequest){
        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()){
            throw new IllegalStateException("User with this email exists");
        }
        User user = User.builder()
                .email(registerRequest.getEmail())
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .phone(registerRequest.getPhone())
                .password(registerRequest.getPassword())
                .role(Role.ADMIN)
                .build();
        userRepository.save(user);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(registerRequest.getEmail(), registerRequest.getPassword())
        );
        String token = jwtService.generateToken(authentication);
        return AuthenticationResponse.builder()
                .token(token)
                .build();


    }
}
