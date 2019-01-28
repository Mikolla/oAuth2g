package ru.springbootstrap.dao;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.springframework.transaction.annotation.Transactional;
import ru.springbootstrap.dao.exceptions.DeleteException;
import ru.springbootstrap.dao.exceptions.MergeException;


import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.util.List;

/**
 * Created by Skrezhet on 09.04.2017.
 */
@Transactional
public abstract class AbstractDao<PK extends Serializable, T> {
    @PersistenceContext
    protected EntityManager entityManager;

    /**
     * Переменная, определяющая второй тип параметризованного абстарктного класса
     */
    private final Class<T> persistentClass;

    @SuppressWarnings("unchecked")
    public AbstractDao() {
        this.persistentClass = (Class<T>) ((ParameterizedType)this.getClass().getGenericSuperclass()).getActualTypeArguments()[1];
    }

    /**
     * Получает сущность по указанному первичному ключу
     * @param key
     * @return
     */
    public T getByKey(PK key) {
        return entityManager.find(persistentClass, key);
    }

    /**
     * Сохраняет сущность в БД
     * @param entity
     */
    public void persist(T entity) {
        entityManager.persist(entity);
    }

    /**
     * Обновляет указанную сущность в БД
     * @param entity
     */
    public void update(T entity) {
        try {
            entityManager.merge(entity);
        } catch (HibernateException e) {
            throw new MergeException("Editable user does not exist");
        }
    }

    /**
     * Удаляет сущность в БД по указанному ключу
     * @param pk
     */
    public void deleteByKey(PK pk) {
        try {
            T entity =  entityManager.find(persistentClass, pk);
            entityManager.remove(entity);
        } catch (HibernateException exp){
            throw new DeleteException("There is no user with the specified ID");
        }
    }

    /**
     * Получаем всё таблицу из БД
     * @return
     */
    public List<T> getAll() {
        String genericClassName = persistentClass.toGenericString();
        //Получаем имя класса (без .class)
        genericClassName = genericClassName.substring(genericClassName.lastIndexOf('.') + 1);
        String hql = "FROM " + genericClassName;
        return entityManager.createQuery(hql).getResultList();
    }

    protected Session getSession() {
        return (Session) entityManager.getDelegate();
    }
}
