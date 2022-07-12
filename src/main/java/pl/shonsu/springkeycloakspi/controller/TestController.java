package pl.shonsu.springkeycloakspi.controller;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.IDToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
public class TestController {

    @GetMapping(path = "/")
    public String index() {
        return "welcome";
    }
    @RolesAllowed("USER")
    @GetMapping("/user")
    public String getAdmin(){
        return "user";
    }
    @RolesAllowed("ADMIN")
    @GetMapping("/admin")
    public String getUser(){
        return "admin";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) throws Exception {
        request.logout();
        return "loggedout";
    }

    @GetMapping("/usertoken")
    public String getUserToken(){
        KeycloakAuthenticationToken authentication =
                (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        Principal principal = (Principal) authentication.getPrincipal();

        String userIdByMapper = "";

        if (principal instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> kPrincipal = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
            IDToken token = kPrincipal.getKeycloakSecurityContext().getIdToken();
            userIdByMapper = token.getOtherClaims().get("user_id").toString();
        }
        return userIdByMapper;
    }
}
