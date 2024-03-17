CREATE DATABASE IF NOT EXISTS authentication;
USE authentication;

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) DEFAULT (uuid()) primary key,
    username VARCHAR(255) UNIQUE NOT NULL ,
    hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    ticket VARCHAR(255) NOT NULL primary key,
    username VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    service VARCHAR(255) NOT NULL
);

CREATE DATABASE IF NOT EXISTS grades;
USE grades;

CREATE TABLE IF NOT EXISTS students (
    userid VARCHAR(36) DEFAULT (uuid()) primary key
);

CREATE TABLE IF NOT EXISTS teachers (
    userid VARCHAR(36) DEFAULT (uuid()) primary key
);

CREATE TABLE IF NOT EXISTS courses (
    id VARCHAR(36) DEFAULT (uuid()) primary key,
    name VARCHAR(255) NOT NULL,
    teacher VARCHAR(36) NOT NULL,
    FOREIGN KEY (teacher) REFERENCES teachers(userid)
);

CREATE TABLE IF NOT EXISTS grades (
    id VARCHAR(36) DEFAULT (uuid()) primary key,
    course VARCHAR(36) NOT NULL,
    student VARCHAR(36) NOT NULL,
    grade VARCHAR(2) NOT NULL,
    notes VARCHAR(255),
    FOREIGN KEY (course) REFERENCES courses(id),
    FOREIGN KEY (student) REFERENCES students(userid)
);

CREATE TABLE IF NOT EXISTS profiles (
    id VARCHAR(36) DEFAULT (uuid()) primary key,
    name VARCHAR(255) NOT NULL,
    picture LONGTEXT NOT NULL,
    FOREIGN KEY (id) REFERENCES students(userid)
);