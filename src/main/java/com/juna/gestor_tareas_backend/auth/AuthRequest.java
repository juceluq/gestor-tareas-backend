package com.juna.gestor_tareas_backend.auth;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password;
}