package com.codestates.hello_oauth2.config;

import com.codestates.hello_oauth2.auth.filter.JwtVerificationFilter;
import com.codestates.hello_oauth2.auth.handler.MemberAccessDeniedHandler;
import com.codestates.hello_oauth2.auth.handler.MemberAuthenticationEntryPoint;
import com.codestates.hello_oauth2.auth.handler.OAuth2MemberSuccessHandler;
import com.codestates.hello_oauth2.auth.jwt.JwtTokenizer;
import com.codestates.hello_oauth2.auth.utils.CustomAuthorityUtils;
import com.codestates.member.service.MemberService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;
    private final MemberService memberService;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils, MemberService memberService) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
        this.memberService = memberService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                .cors(withDefaults())
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint())
                .accessDeniedHandler(new MemberAccessDeniedHandler())
                .and()
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeRequests(authorize-> authorize
                        .antMatchers(HttpMethod.POST, "/*/coffees").hasRole("ADMIN")
                        .antMatchers(HttpMethod.PATCH, "/*/coffees/**").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/coffees").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/coffees/**").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.DELETE, "/*/coffees/**").hasRole("ADMIN")
                        .antMatchers(HttpMethod.POST, "/*/orders").hasRole("USER")
                        .antMatchers(HttpMethod.PATCH, "/*/orders").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/orders").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/orders/**").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.DELETE, "/*/orders/**").hasRole("USER")
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth2->oauth2
                        .successHandler(new OAuth2MemberSuccessHandler(jwtTokenizer, authorityUtils, memberService))
                );
        return http.build();
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PATCH","DELETE"));

        UrlBasedCorsConfigurationSource source =new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer,HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);
            builder.addFilterAfter(jwtVerificationFilter, OAuth2LoginAuthenticationFilter.class);

        }
    }
}
