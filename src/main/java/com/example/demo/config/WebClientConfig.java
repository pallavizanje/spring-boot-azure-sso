package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            AuthenticatedPrincipalOAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();

        var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    public WebClient graphWebClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        var oauth2Function = new org.springframework.security.oauth2.client.web.reactive.function.client
                .ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth2Function.setDefaultOAuth2AuthorizedClient(true);

        return WebClient.builder()
                .apply(oauth2Function.oauth2Configuration())
                .baseUrl("https://graph.microsoft.com")
                .build();
    }
}
