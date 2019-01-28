package ru.springbootstrap.dao.impl.role;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import ru.springbootstrap.dao.AbstractDao;
import ru.springbootstrap.dao.abstraction.role.RoleDao;
import ru.springbootstrap.model.Role;

/**
 * Created by Skrezhet on 09.04.2017.
 */
@Repository
@Transactional
public class RoleDaoImpl extends AbstractDao<Long, Role> implements RoleDao {
    @Override
    public Role getRoleByRoleName(String roleName) {
        return (Role) entityManager.createQuery("FROM Role WHERE Role_name=:roleName").setParameter("roleName", roleName).getSingleResult();
    }
}
