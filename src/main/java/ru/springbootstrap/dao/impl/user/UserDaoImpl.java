package ru.springbootstrap.dao.impl.user;

import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.springbootstrap.dao.abstraction.user.UserDao;
import ru.springbootstrap.model.User;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import java.util.List;

/**
 */
@Repository
public class UserDaoImpl implements UserDao {


    @PersistenceContext
    private EntityManager em;


    @Override
    @Transactional(propagation= Propagation.REQUIRED, rollbackFor=Exception.class)
    public void saveUser(User user) {
            em.persist(user);
    }

    @Override
    @Transactional(propagation= Propagation.SUPPORTS)
    public User getUserById(long id) {
       // TypedQuery<User> query = em.createQuery("SELECT u FROM User u WHERE u.id = :id", User.class);
        User user = em.find(User.class, id);
        return user;
    }

    @Override
    @Transactional(propagation= Propagation.REQUIRED, rollbackFor=Exception.class)
    public void editUser(User user) {
        User merged = em.merge(user);
     }

    @Override
    public User getUserByLogin(String login) {
        return (User) em.createQuery("FROM User WHERE Login=:login").setParameter("login", login).getSingleResult();
    }


    @Override
    @Transactional(propagation= Propagation.REQUIRED, rollbackFor=Exception.class)
    public void deleteUser(long id) {
        //TypedQuery<User> query = em.createQuery("DELETE from User u WHERE u.id = :id", User.class);
        // задать вопрос, почему так не работает
        Query query = em.createQuery("DELETE from User u WHERE u.id = :id");
        query.setParameter("id", id);
        query.executeUpdate();
    }


    @Override
    @Transactional(propagation= Propagation.NOT_SUPPORTED)
    public List<User> getAllUsers() {
        TypedQuery<User> query = em.createQuery("SELECT u FROM User u", User.class);
        return query.getResultList();
    }


}
