package com.example.studentes.repos;

import com.example.studentes.domains.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountsRepo extends JpaRepository<Account, String> {
    Optional<Account> findAccountById(String id);
    Optional<Account> findAccountByUsername(String username);
    Boolean existsAccountByUsername(String username);

    void deleteAccountByUsername(String username);
}
