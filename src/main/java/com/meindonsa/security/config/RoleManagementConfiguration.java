package com.meindonsa.security.config;


import com.meindonsa.config.exception.FunctionalException;
import com.meindonsa.config.utils.Functions;
import jakarta.annotation.PostConstruct;
import lombok.Data;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;


@Data
@Configuration
public class RoleManagementConfiguration {

    @Value("${security.rolesHierarchy}")
    private String rolesHierarchyString;

    List<RoleHierarchyConfiguration> rolesHierarchy = new ArrayList<>();

    @PostConstruct
    public void processRolesHierarchy() {
        List<String> roles = processRolesHierarchyStringList();

        for (String role : roles) {
            RoleHierarchyConfiguration roleHierarchyConfiguration =
                    new RoleHierarchyConfiguration();
            roleHierarchyConfiguration.setRole(role);
            roleHierarchyConfiguration.setHierarchy(Functions.getRemainingList(roles, role));
            rolesHierarchy.add(roleHierarchyConfiguration);
        }
    }

    private List<String> processRolesHierarchyStringList() {
        List<String> roles = new ArrayList<>();
        String[] splitted = rolesHierarchyString.split(">");
        for (String role : splitted) {
            roles.add((role.trim()).split("ROLE_")[1]);
        }
        return roles;
    }

    public RoleHierarchyConfiguration retrieveRoleHierarchy(String roleName) {
        if (roleName == null || roleName.trim().isEmpty())
            throw new FunctionalException("Role cannot be null");
        return rolesHierarchy.stream()
                .filter(role -> role.getRole().equals(roleName))
                .findAny()
                .orElse(null);
    }
}
