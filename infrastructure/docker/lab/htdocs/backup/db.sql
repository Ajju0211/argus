-- ARGUS MOCK LAB — FAKE DATABASE DUMP (synthetic data only)
CREATE TABLE users (
  id integer PRIMARY KEY,
  username varchar(64) NOT NULL,
  password_hash varchar(255) NOT NULL,
  role varchar(32) NOT NULL
);

INSERT INTO users VALUES
  (1, 'admin',  '$2y$10$FakeHashForLabOnlyAdmin',  'administrator'),
  (2, 'jsmith', '$2y$10$FakeHashForLabOnlyJsmith', 'analyst'),
  (3, 'svc',    '$2y$10$FakeHashForLabOnlyService', 'service');

CREATE TABLE api_keys (
  id integer PRIMARY KEY,
  owner varchar(64) NOT NULL,
  key varchar(128) NOT NULL
);

INSERT INTO api_keys VALUES
  (1, 'ci-runner', 'lab_ci_key_5f4dcc3b5aa765d61d8327deb882cf99'),
  (2, 'reporting', 'lab_report_key_6cb75f652a9b52798eb6cf2201057c73');
