CREATE TABLE IF NOT EXISTS t_role (
    id serial NOT NULL,
    role_name VARCHAR(255) UNIQUE NOT NULL,
    create_time timestamp NOT NULL DEFAULT (now())::timestamp,
    update_time timestamp NOT NULL DEFAULT (now())::timestamp,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS r_user_role (
    id serial NOT NULL,
    user_id integer NOT NULL,
    role_id integer NOT NULL,
    FOREIGN KEY (user_id) REFERENCES t_user (id),
    FOREIGN KEY (role_id) REFERENCES t_role (id),
    create_time timestamp NOT NULL DEFAULT (now())::timestamp,
    update_time timestamp NOT NULL DEFAULT (now())::timestamp,
    UNIQUE (user_id, role_id),
    PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_user_role ON r_user_role (user_id, role_id);