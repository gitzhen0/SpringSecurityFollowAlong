package com.marmot.userservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


import javax.persistence.*;

import java.util.ArrayList;
import java.util.Collection;

import static javax.persistence.GenerationType.AUTO;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    //spring security also have a "User" class or interface
    // typically we do "AppUser" here for differentiate,
    //but I am just lazy

    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
    private String username;

    private String password;

    @ManyToMany(fetch = FetchType.EAGER) //I want to load all the roles when i load the user
    private Collection<Role> roles = new ArrayList<>();
}
