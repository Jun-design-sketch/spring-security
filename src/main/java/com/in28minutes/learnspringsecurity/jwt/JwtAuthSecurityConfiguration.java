package com.in28minutes.learnspringsecurity.jwt;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
		http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.httpBasic(withDefaults());
		
//		disable form login
// 		http.formLogin(withDefaults());
//		disable CSRF filter: should use Lambda Customizer
		http.csrf((csrf) -> csrf.disable());
//		use frameOptions to show H2Console
		http.headers((headers) -> headers.frameOptions((frame) -> frame.sameOrigin()));
//		set OAuth2 Resource Server
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		
		return http.build();
	}

//  from JdbcDaoImpl, make schema in H2Database
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
					.setType(EmbeddedDatabaseType.H2)
					.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
					.build();
	}
	
//  use JdbcUserDetailsManager, store same user Credentials into H2Database
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("in28minutes")
//						.password("{noop}dummy")
						.password("dummy")
						.passwordEncoder(str -> passwordEncoder().encode(str))
						.roles("USER")
						.build();
		
		var admin = User.withUsername("admin")
//						.password("{noop}dummy")
						.password("dummy")
						.passwordEncoder(str -> passwordEncoder().encode(str))
						.roles("ADMIN")
						.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);
		
		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}


//	JWT Authentication using Spring Boot's OAuth2 MEMO
//	1.Create Key Pair: java.security.KeyPairGenerator or openssl
//	2.Create RSA Key object using Key Pair: com.nimbusds.jose.jwk.RSAKey
//	3.Create JWKSource(JSON Web Key Source)
//  4.Use RSA Public key for Decoding: NimbusJwtDecoder.withPublicKey(rsaKey().toRSAPublicKey()).build()
//	5.Use JWKSource for Encoding: return new NimbusJwtEncoder(jwkSource())

//  STEP 1: KeyPair
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
//	STEP 2: KeyPair -> RSAKey
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey
					.Builder((RSAPublicKey)keyPair.getPublic())
					.privateKey(keyPair.getPrivate())
					.keyID(UUID.randomUUID().toString())
					.build();
	}

//	STEP 3: RSAKey -> JWKSet -> JWKSource
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);

//		var jwkSource = new JWKSource() {
//
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				return jwkSelector.select(jwkSet);
//			}
//		};
		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}
	
//	STEP 4: RSAKey -> Decoder Build
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

}
