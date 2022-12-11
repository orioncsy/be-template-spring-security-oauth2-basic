package com.codestates.home;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HelloHomeController {
//    @GetMapping("/hello-oauth2")
//    public String home(@AuthenticationPrincipal OAuth2User oAuth2User){
//        System.out.println("User's email in Google: "+ oAuth2User.getAttributes().get("email"));
//        return "hello-oauth2";
//    }
//    private final OAuth2AuthorizedClientService authorizedClientService;
//
//    public HelloHomeController(OAuth2AuthorizedClientService authorizedClientService) {
//        this.authorizedClientService = authorizedClientService;
//    }

    @GetMapping("/hello-oauth2")
    public String home(@RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient){
//        var authorizedClient=
//                authorizedClientService.loadAuthorizedClient("google", authentication.getName());
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        System.out.println("Access Token Value: " + accessToken.getTokenValue());
        System.out.println("Access Token Type: " + accessToken.getTokenType().getValue());
        System.out.println("Access Token Scopes: " + accessToken.getScopes());
        System.out.println("Access Token Issued At: " + accessToken.getIssuedAt());
        System.out.println("Access Token Expires At: " + accessToken.getExpiresAt());
        return "hello-oauth2";
    }
}
