package com.meindonsa.security.config;

import lombok.Data;

import java.util.List;

@Data
public class RoleHierarchyConfiguration {
    private String role;
    private List<String> hierarchy;
}
