package com.marmot.userservice.service;

import com.marmot.userservice.domain.Role;
import com.marmot.userservice.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();

}
