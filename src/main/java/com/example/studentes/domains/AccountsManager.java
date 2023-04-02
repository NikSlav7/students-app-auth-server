package com.example.studentes.domains;

import com.example.studentes.repos.AccountsRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Repository;

import java.util.UUID;


@Repository
@DependsOn("passwordEncoder")
public class AccountsManager implements UserDetailsManager {

    @Autowired
    AccountsRepo accountsRepo;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDetails user) {
        ((Account) user).setPassword(passwordEncoder.encode(user.getPassword()));
        ((Account) user).setId(UUID.randomUUID().toString());
        accountsRepo.save((Account) user);
    }

    @Override
    public void updateUser(UserDetails user) {
        accountsRepo.save((Account) user);
    }

    @Override
    public void deleteUser(String username) {
        accountsRepo.deleteAccountByUsername(username);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return accountsRepo.existsAccountByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return accountsRepo.findAccountByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User wasn't found"));
    }
}
