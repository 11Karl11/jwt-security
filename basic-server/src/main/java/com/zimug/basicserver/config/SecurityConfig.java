package com.zimug.basicserver.config;

import com.zimug.basicserver.config.auth.*;
import com.zimug.basicserver.config.auth.imagecode.CaptchaCodeFilter;
import com.zimug.basicserver.config.auth.smscode.SmsCodeSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Autowired
    private MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Autowired
    private CaptchaCodeFilter captchaCodeFilter;

    @Autowired
    private SmsCodeSecurityConfig smsCodeSecurityConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(captchaCodeFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/signout")
                //.logoutSuccessUrl("/login.html")
                .logoutSuccessHandler(myLogoutSuccessHandler)
                .deleteCookies("JSESSIONID")
                .and().rememberMe()//记住我
                .rememberMeParameter("remember-me-new")
                .rememberMeCookieName("remember-me-cookie")
                .tokenValiditySeconds(2 * 24 * 3600)
                .tokenRepository(persistentTokenRepository())
                .and().csrf().disable()//关闭csrf
                .formLogin()
                .loginPage("/login.html")
                .usernameParameter("uname")
                .passwordParameter("pword")
                .loginProcessingUrl("/login")
                //.failureUrl("/login.html")
                //.defaultSuccessUrl("/index")//和successHandler不能共存
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                .and().apply(smsCodeSecurityConfig).and()
                .authorizeRequests()
                .antMatchers("/login.html", "login", "/kaptcha","/smscode","/smslogin").permitAll()
                .antMatchers("/index").authenticated()
                .anyRequest().access("@rabcService.hasPermission(request,authentication)")
                // .antMatchers("/biz1", "/biz2") //需要对外暴露的资源
                // .hasAnyAuthority("ROLE_user", "ROLE_admin")  //user角色和admin角色都可以访问
                // // .antMatchers("/syslog","/sysuser")
                // // .hasAnyRole("admin")  //admin角色可以访问
                // //.hasAnyAuthority("ROLE_admin")
                // .antMatchers("/syslog").hasAuthority("/syslog")
                // .antMatchers("/sysuser").hasAuthority("/sysuser")
                // .anyRequest().authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/login.html")//配置session失效后跳转到指定的页面
                .sessionFixation()
                .migrateSession()
                .maximumSessions(1)//最大登录数1
                .maxSessionsPreventsLogin(false)//下线之前的
                .expiredSessionStrategy(new MyExpiredSessionStrategy());


    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // auth.inMemoryAuthentication()
        //         .withUser("user")
        //         .password(passwordEncoder().encode("123456"))
        //         .roles("user")
        //         .and()
        //         .withUser("admin")
        //         .password(passwordEncoder().encode("123456"))
        //         .authorities("sys:log", "sys:user")
        //         // .roles("admin")
        //         .and()
        //         .passwordEncoder(passwordEncoder());//配置BCrypt加密
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        //将项目中静态资源路径开放出来
        web.ignoring()
                .antMatchers("/css/**", "/fonts/**", "/img/**", "/js/**");
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }
}