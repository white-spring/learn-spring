package com.white.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.PrintWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**","/images/**");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler((req, resp, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                .loginPage("/login.html")
                .loginProcessingUrl("/dologin")
                //defaultSuccessUrl优先级高于successHandler
//                .defaultSuccessUrl("/hello")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/out")
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("注销成功");
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                            resp.setContentType("application/json;charset=utf-8");
                            PrintWriter out = resp.getWriter();
                            out.write("尚未登录，请先登录");
                            out.flush();
                            out.close();
                        }
                );
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("white")
//                .password("123")
//                .roles("admin");
//    }

    @Bean
    protected UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("admin").password("123qwe").roles("admin").build());
        manager.createUser(User.withUsername("user").password("123").roles("user").build());
        return manager;
    }

    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }
}

