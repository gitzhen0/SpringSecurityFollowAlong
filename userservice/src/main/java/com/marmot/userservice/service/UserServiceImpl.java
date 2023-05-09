package com.marmot.userservice.service;

import com.marmot.userservice.domain.Role;
import com.marmot.userservice.domain.User;
import com.marmot.userservice.repo.RoleRepo;
import com.marmot.userservice.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.fasterxml.jackson.databind.type.LogicalType.Collection;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
// UserService is the normal Service
// UserDetailsService is some stuff from the framework.
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    private final PasswordEncoder passwordEncoder;

    // this is the only method overriding to the UserDetailService
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if (user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        }else{
            log.info("User is found in database {}", username);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // loop through all the roles this user has
        user.getRoles().forEach(role -> {
            //for each role, we create a SimpleGrantedAuthority, and then add it to our authorities list
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        // here, we put user's username, password, authority(role) into User
        // since we also have a User class, and here is different one, so we used the full path
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
        // authorities list is passed in as parameter
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }


}
