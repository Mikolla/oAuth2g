package ru.springbootstrap.config.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.springbootstrap.model.User;
import ru.springbootstrap.service.abstraction.user.UserService;



@Service
public class AuthenticationService implements UserDetailsService {
    @Autowired
    UserService service;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = service.getUserByLogin(username);

        if(user == null) {
            throw  new UsernameNotFoundException("Username " + username + " not found");
        }

        return user;
    }
}
