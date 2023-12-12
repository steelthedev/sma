package dev.steelthedev.sma.config;

import dev.steelthedev.sma.auth.TokenResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class JwtService {
    private final JwtEncoder jwtEncoder;

    public TokenResponse generateTokens(Authentication authentication){
        Instant now = Instant.now();

        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet accessTokenClaimsSet = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .claim("scope",scope)
                .claim("email",authentication.getName())
                .build();
        JwtClaimsSet refreshTokenClaimsSet = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(30, ChronoUnit.DAYS))
                .claim("scope",scope)
                .claim("email",authentication.getName())
                .build();

        String accessToken = this.jwtEncoder.encode(JwtEncoderParameters.from(accessTokenClaimsSet)).getTokenValue();
        String refreshToken = this.jwtEncoder.encode(JwtEncoderParameters.from(refreshTokenClaimsSet)).getTokenValue();
        return TokenResponse.builder()
                .refreshToken(refreshToken)
                .accessToken(accessToken)
                .build();

    }
}
