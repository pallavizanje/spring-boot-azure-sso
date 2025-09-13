package com.example.demo.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class GraphGroupsResponse {

    @JsonProperty("value")
    private List<GroupItem> value;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GroupItem {
        private String id;
        private String displayName;
        private String odataType;
    }
}
