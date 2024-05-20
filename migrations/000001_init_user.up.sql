CREATE EXTENSION IF NOT EXISTS citext;

CREATE DOMAIN email_address AS citext CHECK (
    value ~ '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
);

CREATE TABLE IF NOT EXISTS t_user (
    id serial NOT NULL,
    username character varying(128) UNIQUE NOT NULL,
    email email_address UNIQUE NOT NULL,
    salt character varying(64) NOT NULL,
    password character varying(128) NOT NULL,
    validate boolean NOT NULL DEFAULT false,
    create_time timestamp NOT NULL DEFAULT (now())::timestamp,
    update_time timestamp NOT NULL DEFAULT (now())::timestamp,
    PRIMARY KEY (id)
);