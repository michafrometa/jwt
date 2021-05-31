package com.inezpre5.jwt.repository;

import com.inezpre5.jwt.domain.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByNombreUsuario(String nu);
        boolean existsByNombreUsuario(String nu);
        boolean existsByEmail(String email);
}