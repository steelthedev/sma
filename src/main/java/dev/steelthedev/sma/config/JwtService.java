package dev.steelthedev.sma.config;


import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class JwtService {
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

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
                .claim("subject",authentication.getName())
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

    public Map<String, Object> extractClaims(String jwt){
        Jwt decodedJwt = jwtDecoder.decode(jwt);
        return decodedJwt.getClaims();
    }

    public boolean isExpired(String jwt){
        Instant expirationDate = (Instant) extractClaims(jwt).get("exp");
        Date exp = Date.from(expirationDate);
        return exp.before(new Date());
    }

    public  boolean isTokenValid(String token, UserDetails userDetails){
        final String username =(String) extractClaims(token).get("subject");
        return (username.equals(userDetails.getUsername()) && !isExpired(token));
    }
}
