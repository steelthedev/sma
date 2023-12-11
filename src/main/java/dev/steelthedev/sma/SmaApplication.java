package dev.steelthedev.sma;

import dev.steelthedev.sma.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({RsaKeyProperties.class})
@SpringBootApplication
public class SmaApplication {

	public static void main(String[] args) {
		SpringApplication.run(SmaApplication.class, args);
	}

}
