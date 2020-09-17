package com.github.mikereem.apple.signin.util;

import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.mikereem.apple.signin.model.Header;
import com.github.mikereem.apple.signin.model.TokenResponse;
import com.github.mikereem.apple.signin.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Main utility class for validating Apple ID Signins.
 * 
 * @author mikereem
 *
 */
public class AppleSigninUtil {

	private static final Logger LOGGER = Logger.getLogger(AppleSigninUtil.class);

	private static String APPLE_APPLEID_URL = "https://appleid.apple.com";
	private static String APPLE_AUTH_URL = "https://appleid.apple.com/auth/token";
	private static String APPLE_PUBLIC_KEY_URL = "https://appleid.apple.com/auth/keys";

	private static ObjectMapper objectMapper = new ObjectMapper();

	private static String keyId;
	private static String teamId;

	private static PrivateKey privateKey;
	private static Map<String, PublicKey> publicKeys;

	/**
	 * For further usage, the AppleSigninUtil should be initialized first with
	 * your Apple App's details, which can be found at
	 * <a href="developer.apple.com">Apple Developer</a>.
	 * 
	 * @param keyId
	 *            App Key ID
	 * @param teamId
	 *            Apple Team ID
	 * @param privateKeyReader
	 *            Apple private keystore (p8 file)
	 * 
	 * @throws IOException
	 */
	public static void init(String keyId, String teamId, Reader privateKeyReader) throws IOException {
		AppleSigninUtil.keyId = keyId;
		AppleSigninUtil.teamId = teamId;
		AppleSigninUtil.privateKey = getPrivateKey(privateKeyReader);

		objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
	}

	private static PrivateKey getPrivateKey(Reader privateKeyReader) throws IOException {
		PEMParser pemParser = new PEMParser(privateKeyReader);
		JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();
		PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
		PrivateKey key = pemKeyConverter.getPrivateKey(keyInfo);
		pemParser.close();
		return key;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static PublicKey getPublicKey(Header header) {
		PublicKey publicKey = null;
		try {
			if (publicKeys == null || publicKeys.size() == 0) {
				String publicKeyResult = get(APPLE_PUBLIC_KEY_URL);
				if (publicKeyResult == null || publicKeyResult.length() == 0) {
					return null;
				}
				publicKeys = new HashMap<>();

				Map maps = objectMapper.readValue(publicKeyResult, Map.class);
				List<Map> keys = (List<Map>) maps.get("keys");
				for (Map key : keys) {
					if (key != null) {
						Base64.decodeBase64(key.get("n").toString());
						byte[] nBytes = Base64.decodeBase64(key.get("n").toString());
						byte[] eBytes = Base64.decodeBase64(key.get("e").toString());
						BigInteger modulus = new BigInteger(1, nBytes);
						BigInteger publicExponent = new BigInteger(1, eBytes);
						RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
						String algorithm = key.get("kty").toString(); // kty
																		// will
																		// be
																		// "RSA"
						KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
						publicKey = keyFactory.generatePublic(publicKeySpec);

						String mapKey = String.format("%s_%s", key.get("kid"), key.get("alg"));
						publicKeys.put(mapKey, publicKey);
					}
				}
			}

			String headerKey = String.format("%s_%s", header.getKid(), header.getAlg());
			publicKey = publicKeys.get(headerKey);
		} catch (Throwable t) {
			LOGGER.error("Error during getting apple public key. Reason:" + t.getMessage(), t);
		}
		return publicKey;
	}

	private static String getToken(String clientId) {
		String token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).setIssuer(teamId)
				.setAudience(APPLE_APPLEID_URL).setSubject(clientId)
				.setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 5)))
				.setIssuedAt(new Date(System.currentTimeMillis())).signWith(privateKey, SignatureAlgorithm.ES256)
				.compact();

		return token;
	}

	/**
	 * Authorize a client request. You have to provide the parameters received
	 * from your client. Based on those, this method will try to authorize the
	 * client to Apple's server and will validate the received parameters.
	 * 
	 * If the authorization is successful, then a JWT Claims object is returned,
	 * which can be later used to read out public information from.
	 * 
	 * @param clientId
	 *            The Apple Client ID. The same application can have multiple
	 *            clients: a webclient, mobile client. Each will have have its
	 *            own Client ID at Apple. After the client receives the
	 *            identityToken and authorizationCode, those will be only valid
	 *            for that specific clientID. We can validate them only by
	 *            providing the clientID to Apple.
	 * @param identityToken
	 *            The identityToken received by the client from Apple.
	 * @param code
	 *            The authorizationCode received by the client from Apple.
	 * @param redirectURI
	 *            Optional parameter to send to Apple as redirect_uri. This is
	 *            not required and can be null if you just want to use the
	 *            redirect uri defined for your app at Apple Developer.
	 * @return a JWT Claims object. Store it for later use with this utility
	 *         class to get info about the authorized user.
	 * 
	 * @throws JsonParseException
	 * @throws JsonMappingException
	 * @throws IOException
	 */
	public static Claims authorize(String clientId, String identityToken, String code, String redirectURI)
			throws JsonParseException, JsonMappingException, IOException {
		LOGGER.info("Apple authorization validation");
		// get the subject received from the client
		String clientSubject = getSubject(identityToken);

		// verifying the code by the apple server
		String token = getToken(clientId);
		LOGGER.debug("Authorize with token:" + token);

		Map<String, String> params = new HashMap<>();
		params.put("client_id", clientId);
		params.put("client_secret", token);
		params.put("code", code);
		params.put("grant_type", "authorization_code");
		if (redirectURI != null) {
			params.put("redirect_uri", redirectURI);
		}
		String response = post(APPLE_AUTH_URL, params);
		LOGGER.info("Apple authorization response:" + response);

		TokenResponse tokenResponse = objectMapper.readValue(response, TokenResponse.class);
		if (tokenResponse.getError() != null && tokenResponse.getError().length() > 0) {
			LOGGER.warn("Error during verification of the code. Reason:" + tokenResponse.getError());
			return null;
		}

		String serverSubject = getSubject(tokenResponse.getId_token());
		if (!serverSubject.equals(clientSubject)) {
			LOGGER.warn("Validation failed, subject does not match!");
			return null;
		}

		return getClaims(tokenResponse.getId_token());
	}

	public static User parseUser(String userJson) throws JsonParseException, JsonMappingException, IOException {
		User user = objectMapper.readValue(userJson, User.class);
		return user;
	}

	/**
	 * Get the email field from the JWT Claims.
	 * 
	 * @param claims
	 *            the JWT Claims received by the authorize method.
	 * 
	 * @return the email of the authenticated user
	 */
	public String getEmail(Claims claims) {
		return claims.get("email", String.class);
	}

	/**
	 * Get the subject (User ID at Apple) from the JWT Claims.
	 * 
	 * @param claims
	 *            the JWT Claims received by the authorize method.
	 * 
	 * @return the user ID at Apple stored in the subject
	 */
	public String getSubject(Claims claims) {
		return claims.get("sub", String.class);
	}

	/**
	 * Check if provided email address is a private one. User's can hide their
	 * real email address by a relay email address provided by Apple. You can
	 * get info about the user hidden the real email address or not.
	 * 
	 * @param claims
	 *            the JWT Claims received by the authorize method.
	 * @return true if the real email is hidden
	 */
	public Boolean isPrivateEmail(Claims claims) {
		return claims.get("is_private_email", Boolean.class);
	}

	/**
	 * Get the subject (User ID at Apple) from the identityToken.
	 * 
	 * @param identityToken
	 *            received by the client. You can do additional validation if
	 *            the subjects are the same in the identityToken and in the JWT
	 *            Claims.
	 * @return the user ID at Apple stored in the subject
	 */
	private static String getSubject(String identityToken) {
		return getClaims(identityToken).getSubject();
	}

	private static Claims getClaims(String identityToken) {
		Header header = parseHeader(identityToken);
		PublicKey publicKey = getPublicKey(header);
		JwtParser jwtParser = Jwts.parser().setSigningKey(publicKey);
		Jws<Claims> jws = jwtParser.parseClaimsJws(identityToken);
		return jws.getBody();
	}

	private static Header parseHeader(String identityToken) {
		Header header = null;
		try {
			String[] arrToken = identityToken.split("\\.");
			if (arrToken == null || arrToken.length != 3) {
				return null;
			}

			String text = new String(Base64.decodeBase64(arrToken[0]), "utf-8");
			header = objectMapper.readValue(text, Header.class);
		} catch (Throwable t) {
			LOGGER.warn("Unable to parse the Identity Token header.", t);
		}
		return header;
	}

	private static String get(String url) {
		String result = null;
		CloseableHttpClient httpClient = null;
		HttpResponse response = null;
		Integer statusCode = null;
		String reason = null;
		try {
			httpClient = HttpClientBuilder.create().build();
			HttpGet httpGet = new HttpGet(url);
			response = httpClient.execute(httpGet);
			statusCode = response.getStatusLine().getStatusCode();
			reason = response.getStatusLine().getReasonPhrase();
			HttpEntity entity = response.getEntity();
			result = EntityUtils.toString(entity, "UTF-8");

			if (statusCode != 200) {
				LOGGER.error(String.format("HTTP GET failed to URL:%s. Status code: %s. Reason:%s. Result:%s.", url,
						statusCode, reason, result));
			}
		} catch (Throwable t) {
			LOGGER.error(
					String.format("HTTP GET failed to URL:%s. Status code: %s. Reason:%s.", url, statusCode, reason),
					t);
		}
		return result;
	}

	private static String post(String url, Map<String, String> params) {
		String result = null;
		CloseableHttpClient httpClient = null;
		HttpResponse response = null;
		Integer statusCode = null;
		String reason = null;
		try {
			httpClient = HttpClientBuilder.create().build();
			HttpPost httpPost = new HttpPost(url);
			httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
			List<NameValuePair> nameValues = new ArrayList<>();
			for (Entry<String, String> entry : params.entrySet()) {
				nameValues.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
			}
			UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(nameValues);
			httpPost.setEntity(formEntity);
			response = httpClient.execute(httpPost);
			statusCode = response.getStatusLine().getStatusCode();
			reason = response.getStatusLine().getReasonPhrase();
			HttpEntity entity = response.getEntity();
			result = EntityUtils.toString(entity, "UTF-8");

			if (statusCode != 200) {
				LOGGER.error(String.format(
						"HTTP POST failed to URL:%s. Status code: %s. Reason:%s. Parameters:%s. Result:%s.", url,
						statusCode, reason, objectMapper.writeValueAsString(params), result));
			}
			EntityUtils.consume(entity);
		} catch (Throwable t) {
			try {
				LOGGER.error(String.format("HTTP POST failed to URL:%s. Status code: %s. Reason:%s. Parameters:%s.",
						url, statusCode, reason, objectMapper.writeValueAsString(params)));
			} catch (JsonProcessingException e) {
				LOGGER.error(e, e);
			}
		}
		return result;
	}
}
