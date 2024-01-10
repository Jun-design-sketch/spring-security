package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(jsr250Enabled=true, securedEnabled=true)
public class BasicAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(
				(requests) -> requests
								// use RequestMatchers: can set specific rules
								.requestMatchers("/users").hasRole("USER")
								.requestMatchers("/admin/").hasRole("USER")
								.anyRequest().authenticated());
		http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.httpBasic(withDefaults());
		
//		disable form login
// 		http.formLogin(withDefaults());

//		disable CSRF filter: should use Lambda Customizer
//		http.csrf().disable();
		http.csrf((csrf) -> csrf.disable());

//		use frameOptions to show H2Console
//		http.headers().frameOptions().sameOrigin();
		http.headers((headers) -> headers.frameOptions((frame) -> frame.sameOrigin()));
		return http.build();
	}

// InMemory User
//	@Bean
//	public UserDetailsService userDetailService() {
//		
//		var user = User.withUsername("in28minutes")
//						.password("{noop}dummy")
//						.roles("USER")
//						.build();
//		
//		var admin = User.withUsername("admin")
//						.password("{noop}dummy")
//						.roles("ADMIN")
//						.build();
//		
//		
//		
//		return new InMemoryUserDetailsManager(user, admin);
//	}

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

}
