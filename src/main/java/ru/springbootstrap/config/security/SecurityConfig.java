package ru.springbootstrap.config.security;




import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;
import ru.springbootstrap.config.security.handlers.CustomAuthenticationSuccessHandler;
import ru.springbootstrap.config.security.service.AuthenticationService;

//https://www.baeldung.com/spring-security-5-oauth2-login


@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private CustomAuthenticationSuccessHandler successHandler;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(authenticationService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        filter.setEncoding("UTF-8");
        filter.setForceEncoding(true);
        http.csrf().disable().addFilterBefore(filter, CsrfFilter.class);
        http.authorizeRequests()
                .antMatchers("/registration").permitAll()
                .antMatchers("/user/**").hasAnyAuthority("Admin", "User")
              //  .antMatchers("/user/**").hasAnyAuthority("Admin")
                .antMatchers("/admin/**").hasAnyAuthority("Admin")
                .antMatchers("/").hasAnyAuthority("Admin", "User")
                .and().formLogin().loginPage("/login1").successHandler(successHandler)
                .usernameParameter("username").passwordParameter("password")
                .and().exceptionHandling().accessDeniedPage("/access_denied")
                .and().oauth2Login()
         ;


    }




}
