package com.rumanblogs.googledrive.usingjwt;

import org.mule.api.MuleEventContext;
import org.mule.api.lifecycle.Callable;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.json.jackson2.JacksonFactory;

public class CreateDriveJWT implements Callable {

	static JacksonFactory JSON_FACTORY = new JacksonFactory();

	private static String authorizeWithJWT() {
		long now = System.currentTimeMillis();
		try {
			GoogleCredential credential = GoogleCredential
					.fromStream(CreateDriveJWT.class.getResourceAsStream("/mule-googledrive-serviceacct.json"));
			PrivateKey privateKey = credential.getServiceAccountPrivateKey();
			String accountId = credential.getServiceAccountId();
			String audience = "https://accounts.google.com/o/oauth2/token";

			Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey);
			String signedJWT = JWT.create()
									.withIssuer(accountId)
									.withAudience(audience)
									.withIssuedAt(new Date(now))
									.withClaim("scope", "https://www.googleapis.com/auth/drive")
									.withExpiresAt(new Date(now + 3600 * 1000L)).sign(algorithm);
			return signedJWT;
		} catch (Exception ex) {
			return ex.getMessage();
		}
	}

	@Override
	public Object onCall(MuleEventContext eventContext) throws Exception {
		String jwtToken = authorizeWithJWT();
		eventContext.getMessage().setInvocationProperty("googledriveJWT", jwtToken);
		return eventContext;
	}
}
