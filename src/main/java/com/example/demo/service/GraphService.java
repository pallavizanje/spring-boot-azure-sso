package com.example.demo.service;

import com.example.demo.dto.GraphGroupsResponse;
import com.example.demo.dto.UserProfileDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.web.reactive.function.client
        .ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Service
@RequiredArgsConstructor
public class GraphService {

    private final WebClient graphWebClient;

    public UserProfileDto getUserProfile(OAuth2AuthorizedClient authorizedClient) {
        return graphWebClient
                .get()
                .uri("/v1.0/me")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(UserProfileDto.class)
                .block();
    }

    public List<String> getUserGroups(OAuth2AuthorizedClient authorizedClient) {
        GraphGroupsResponse resp = graphWebClient
                .get()
                .uri("/v1.0/me/memberOf")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(GraphGroupsResponse.class)
                .block();

        if (resp == null || resp.getValue() == null) return List.of();
        return resp.getValue().stream()
                .map(item -> item.getDisplayName())
                .filter(name -> name != null && !name.isBlank())
                .collect(Collectors.toList());
    }
}
