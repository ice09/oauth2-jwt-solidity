package de.traxpay.spv.ipi2blockchain.runner;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Component
public class TokenCreator {

	private ObjectMapper objectMapper;

	@Value("${security.oauth2.access-token-uri}")
	private String url;

	@Value("${security.oauth2.client-id}")
	private String clientId;

	@Value("${security.oauth2.grant_type}")
	private String grantType;

	@Value("${security.oauth2.username}")
	private String userName;

	@Value("${security.oauth2.password}")
	private String password;

	@Value("${security.oauth2.client-secret}")
	private String clientSecret;

	@Value("${keycloak.cert.url}")
	private String keycloakCertUrl;

	public TokenCreator() {
		objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	public AuthenticationDataDto retrieveToken() {
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			RestTemplate restTemplate = new RestTemplate();

			MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
			map.add("grant_type", grantType);
			map.add("username", userName);
			map.add("password", password);
			map.add("client_id", clientId);
			map.add("client_secret", clientSecret);

			HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(map, headers);
			ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
			return objectMapper.readerFor(AuthenticationDataDto.class).readValue(response.getBody());
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	public String getKeycloakCertUrl() {
	    return keycloakCertUrl;
    }
}
