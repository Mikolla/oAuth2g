package ru.springbootstrap.dao;

import java.io.Serializable;
import java.util.List;

/**
 * Created by Skrezhet on 09.04.2017.
 */
public interface GenericDao<PK extends Serializable, T> {
    T getByKey(PK id);

    void persist(T entity);

    void update(T group);

    void deleteByKey(PK id);

    List<T> getAll();
}
