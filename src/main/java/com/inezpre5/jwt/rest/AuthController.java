package com.inezpre5.jwt.rest;

import com.inezpre5.jwt.domain.Rol;
import com.inezpre5.jwt.domain.Usuario;
import com.inezpre5.jwt.domain.enums.RolNombre;
import com.inezpre5.jwt.dto.JwtDTO;
import com.inezpre5.jwt.dto.LoginUsuario;
import com.inezpre5.jwt.dto.NuevoUsuario;
import com.inezpre5.jwt.security.jwt.JwtProvider;
import com.inezpre5.jwt.service.RolService;
import com.inezpre5.jwt.service.UsuarioService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final UsuarioService usuarioService;

    private final RolService rolService;

    private final JwtProvider jwtProvider;

    public AuthController(PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, UsuarioService usuarioService, RolService rolService, JwtProvider jwtProvider) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.usuarioService = usuarioService;
        this.rolService = rolService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/nuevo")
    public ResponseEntity<?> nuevo(@Valid @RequestBody NuevoUsuario nuevoUsuario, BindingResult bindingResult) {
        if (bindingResult.hasErrors())
            return new ResponseEntity<>("campos vacíos o email inválido", HttpStatus.BAD_REQUEST);
        if (usuarioService.existePorNombre(nuevoUsuario.getNombreUsuario()))
            return new ResponseEntity<>("ese nombre ya existe", HttpStatus.BAD_REQUEST);
        if (usuarioService.existePorEmail(nuevoUsuario.getEmail()))
            return new ResponseEntity<>("ese email ya existe", HttpStatus.BAD_REQUEST);
        Usuario usuario = new Usuario()
                .nombre(nuevoUsuario.getNombre())
                .nombreUsuario(nuevoUsuario.getNombreUsuario())
                .email(nuevoUsuario.getEmail())
                .password(passwordEncoder.encode(nuevoUsuario.getPassword()));

        if (!nuevoUsuario.getRoles().isEmpty()) {
            Set<Rol> roles = new HashSet<>();
            nuevoUsuario.getRoles().forEach(rol -> {
                switch (rol) {
                    case "admin":
                        Optional<Rol> rolAdmin = rolService.getByRolNombre(RolNombre.ROLE_ADMIN);
                        rolAdmin.ifPresent(roles::add);
                        break;
                    default:
                        Optional<Rol> rolUser = rolService.getByRolNombre(RolNombre.ROLE_USER);
                        rolUser.ifPresent(roles::add);
                }
            });
            usuario.setRoles(roles);
        }
        usuarioService.guardar(usuario);
        return new ResponseEntity<>("usuario guardado", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtDTO> login(@Valid @RequestBody LoginUsuario loginUsuario, BindingResult bindingResult) {
        if (bindingResult.hasErrors())
            return new ResponseEntity("campos vacíos o email inválido", HttpStatus.BAD_REQUEST);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginUsuario.getNombreUsuario(), loginUsuario.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateToken(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        JwtDTO jwtDTO = new JwtDTO(jwt, userDetails.getUsername(), userDetails.getAuthorities());
        return new ResponseEntity<>(jwtDTO, HttpStatus.OK);
    }
}
