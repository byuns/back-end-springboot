package com.mycompany.backend.config;

import javax.annotation.Resource;

import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.mycompany.backend.security.JwtAuthenticationFilter;

import lombok.extern.log4j.Log4j2;

@Log4j2
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

  @Resource
  private RedisTemplate<String, String> redisTemplate;
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("실행");
    //서버 세션 비활성화
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    
    //폼 로그인 비활성화
    http.formLogin().disable();
    
    //사이트 간 요청 위조 방지 비활성화
    http.csrf().disable();
    
    //요청 경로 권한 설정
    http.authorizeRequests()
      .antMatchers("/board/**").authenticated()
      .antMatchers("/**").permitAll(); 
    
    //JWT 토큰 인증 필터 추가
    http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    
    //CORS 설정(다른 도메인의 JavaScript로 접근을 허용)
    http.cors();
 
 }
  //다른 곳에서 사용하지 않으므로  @Bean(관리 객체)으로 생성할 필요는 없다.
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter();
    jwtAuthenticationFilter.setRedisTemplate(redisTemplate);
    return jwtAuthenticationFilter;
  }
  


  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    log.info("실행");
    
    //MPA 폼 인증 방식에서 사용(JWT 인증 방식에서는 사용하지 않음)
    /*DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(new CustomUserDetailsService());
    provider.setPasswordEncoder(passwordEncoder());
    auth.authenticationProvider(provider); */
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    log.info("실행");
    DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
    defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchyImpl());   
    web.expressionHandler(defaultWebSecurityExpressionHandler);
    
    //MPA에서 시큐리티를 적용하지 않는 경로 설정
    /*web.ignoring()
    .antMatchers("/images/**")
    .antMatchers("/css/**")
    .antMatchers("/js/**")
    .antMatchers("/bootstrap/**")
    .antMatchers("/jquery/**")
    .antMatchers("/favicon.ico");*/
  }
  
  @Bean
  public PasswordEncoder passwordEncoder() {
    //return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // 암호화 방식을 바꿀 것이다
    return new BCryptPasswordEncoder(); // 암호화 방식을 바꾸지 않을 것이다.
  }
  
  @Bean
  public RoleHierarchyImpl roleHierarchyImpl() {
     log.info("실행");
     RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
     roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
     return roleHierarchyImpl;
  }
  
  //Rest API에서만 사용
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    log.info("실행");
      CorsConfiguration configuration = new CorsConfiguration();
      //모든 요청 사이트 허용
      configuration.addAllowedOrigin("*");
      //모든 요청 방식 허용
      configuration.addAllowedMethod("*");
      //모든 요청 헤더 허용
      configuration.addAllowedHeader("*");
      //모든 URL 요청에 대해서 위 내용을 적용
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
  }
}
