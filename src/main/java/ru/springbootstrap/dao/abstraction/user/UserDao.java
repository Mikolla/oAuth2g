package ru.springbootstrap.dao.abstraction.user;



import ru.springbootstrap.model.User;

import java.util.List;

public interface UserDao {

    void saveUser(User user);

   User getUserById(long id);

    void editUser(User user);


    User getUserByLogin(String login);

    void deleteUser(long id);

    List<User> getAllUsers();

}
