package ru.springbootstrap.dao.abstraction.role;


import ru.springbootstrap.dao.GenericDao;
import ru.springbootstrap.model.Role;

/**
 * Created by Skrezhet on 09.04.2017.
 */
public interface RoleDao extends GenericDao<Long, Role> {
    Role getRoleByRoleName(String roleName);
}
