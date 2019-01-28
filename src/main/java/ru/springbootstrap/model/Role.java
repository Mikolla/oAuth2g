package ru.springbootstrap.model;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;


@Entity
@Table(name = "Roles")
public class Role implements GrantedAuthority {
    @Id
    @Column(name = "ID")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "Role_name", nullable = false)
    private String roleName;

    @ManyToMany(fetch = FetchType.EAGER, targetEntity = User.class)
    @JoinTable(name = "users_roles_ids", joinColumns = {@JoinColumn(name = "role_id")},
            inverseJoinColumns = {@JoinColumn(name = "user_id")})
    private Set<User> users = new HashSet<>();

    public Role() {
    }

    public Role(String roleName) {
        this.roleName = roleName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Role role = (Role) o;

        return roleName.equals(role.roleName);
    }

    @Override
    public int hashCode() {
        return roleName.hashCode();
    }

    @Override
    public String getAuthority() {
        return roleName;
    }
}
