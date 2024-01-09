package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
		http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.httpBasic(withDefaults());
		
//		disable form login
// 		http.formLogin(withDefaults());

//		disable CSRF filter: should use Lambda Customizer
//		http.csrf().disable();
		http.csrf((csrf) -> csrf.disable());

		return http.build();
	}
	
	@Bean
	public UserDetailsService userDetailService() {
		
		var user = User.withUsername("in28minutes")
						.password("{noop}dummy")
						.roles("USER")
						.build();
		
		var admin = User.withUsername("admin")
						.password("{noop}dummy")
						.roles("ADMIN")
						.build();
		
		
		
		return new InMemoryUserDetailsManager(user, admin);
	}
}
