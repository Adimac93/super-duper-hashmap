CREATE TABLE users (
                       id UUID DEFAULT gen_random_uuid(),
                       username TEXT NOT NULL,
                       PRIMARY KEY (id)
);

CREATE TABLE credentials (
                             user_id UUID,
                             email TEXT NOT NULL,
                             password TEXT NOT NULL,
                             PRIMARY KEY (user_id),
                             FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE sessions (
                          id UUID DEFAULT gen_random_uuid(),
                          user_id UUID NOT NULL,
                          PRIMARY KEY (id),
                          FOREIGN KEY (user_id) REFERENCES users(id)
);
