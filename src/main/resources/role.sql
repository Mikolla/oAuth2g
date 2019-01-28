CREATE TABLE IF NOT EXISTS roles
(id BIGINT AUTO_INCREMENT, Role_name VARCHAR(30),
 PRIMARY KEY(id), UNIQUE (Role_name));
INSERT IGNORE INTO roles (Role_name) VALUE ('Admin');
INSERT IGNORE INTO roles (Role_name) VALUE ('User');


CREATE TABLE users_roles_ids
(
    role_id bigint(20) NOT NULL,
    user_id bigint(20) NOT NULL,
    CONSTRAINT `PRIMARY` PRIMARY KEY (user_id, role_id),
    CONSTRAINT FK_p2bj7j0yrjf0v81glvqftnrbf FOREIGN KEY (role_id) REFERENCES roles (ID),
    CONSTRAINT FK_d95la5s35s73j0pkfgqrkx1w5 FOREIGN KEY (user_id) REFERENCES users (ID)
);
CREATE INDEX FK_p2bj7j0yrjf0v81glvqftnrbf ON users_roles_ids (role_id);


CREATE TABLE users
(
    id bigint(20) PRIMARY KEY NOT NULL AUTO_INCREMENT,
    login varchar(255),
    name varchar(255),
    password varchar(255),
    role varchar(255)
);
CREATE UNIQUE INDEX UK_ow0gan20590jrb00upg3va2fn ON users (login);
CREATE UNIQUE INDEX UK_3g1j96g94xpk3lpxl2qbl985x ON users (name);