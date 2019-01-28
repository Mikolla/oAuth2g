package ru.springbootstrap.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;


@Entity
@Table(name = "Users")
public class User implements UserDetails {
    @Id
    @Column(name = "ID")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "Name", length = 20, nullable = false)
    private String name;

    @Column(name = "Login", length = 20, nullable = false, unique = true)
    private String login;

    @Column(name = "Password", length = 20, nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER, targetEntity = Role.class)
    @JoinTable(name = "users_roles_ids", joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<Role> roles = new HashSet<>();

    public User() {
    }

    public User(String name, String login, String password, Set<Role> roles) {
        this.name = name;
        this.login = login;
        this.password = password;
        this.roles = roles;
    }

    public User(Long id, String name, String login, String password, Set<Role> roles) {
        this.id = id;
        this.name = name;
        this.login = login;
        this.password = password;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return login;
    }

    /**
     * Метод показвает, не истёк ли срок учётной записи (если false - истёк)
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Метод показывает, не заплокирована ли учётная запись (если false - заблокирован)
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Метод показвает, не истёк ли срок данных учётной записи (если false - истёк)
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        User user = (User) o;

        if (!name.equals(user.name)) return false;
        if (!login.equals(user.login)) return false;
        if (!password.equals(user.password)) return false;
        return roles.equals(user.roles);
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + login.hashCode();
        result = 31 * result + password.hashCode();
        result = 31 * result + roles.hashCode();
        return result;
    }
}
