package dev.steelthedev.sma.auth;

import dev.steelthedev.sma.config.JwtService;
import dev.steelthedev.sma.user.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final  JwtService jwtService;
    public LoginResponse login(LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
        );
        var user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow();
        String token = jwtService.generateToken(authentication);
        return LoginResponse.builder()
                .token(token)
                .build();
    }
}
