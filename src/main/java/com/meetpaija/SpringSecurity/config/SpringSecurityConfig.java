package com.meetpaija.SpringSecurity.config;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configurable
@EnableWebSecurity
public class SpringSecurityConfig  extends WebSecurityConfigurerAdapter{

	
	@SuppressWarnings("deprecation")
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().passwordEncoder(NoOpPasswordEncoder.getInstance())
		.withUser("meet").password("meet").roles("USER").and()
		.withUser("admin").password("admin").roles("ADMIN");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http                               
        .authorizeRequests()
        .antMatchers("/api/hello/**").access("hasRole('ADMIN')")
            .and()
        .httpBasic();
		
		http.csrf().disable();
	}
	
}
