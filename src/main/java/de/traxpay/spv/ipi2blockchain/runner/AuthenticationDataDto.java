package de.traxpay.spv.ipi2blockchain.runner;

import lombok.Data;

@Data
public class AuthenticationDataDto {

	String access_token;
	int expires_in;
	int refresh_expires_in;
	String refresh_token;
	String token_type;

}
