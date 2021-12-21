# learn-spring
spring 学习工程

## 一些比较常见的认证方式
* HTTP BASIC authentication headers：基于IETF RFC 标准。
* HTTP Digest authentication headers：基于IETF RFC 标准。
* HTTP X.509 client certificate exchange：基于IETF RFC 标准。
* LDAP：跨平台身份验证。
* Form-based authentication：基于表单的身份验证。
* Run-as authentication：用户用户临时以某一个身份登录。
* OpenID authentication：去中心化认证。
* 除了这些常见的认证方式之外，一些比较冷门的认证方式，Spring Security 也提供了支持。
* Jasig Central Authentication Service：单点登录。
* Automatic "remember-me" authentication：记住我登录（允许一些非敏感操作）。
* Anonymous authentication：匿名登录。

## 创建数据库表(mysql)
```sql
create table users(username varchar(50) not null primary key,password varchar(500) not null,enabled boolean not null);
create table authorities (username varchar(50) not null,authority varchar(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
create unique index ix_auth_username on authorities (username,authority);
```