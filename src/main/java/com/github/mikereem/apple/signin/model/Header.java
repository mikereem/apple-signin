package com.github.mikereem.apple.signin.model;

/**
 * Header model.
 * 
 * @author mikereem
 *
 */
public class Header {

	private String kid;
	private String alg;

	/**
	 * A 10-character key identifier generated for the Sign in with Apple private key associated with your developer account.
	 */
	public String getKid() {
		return kid;
	}

	public void setKid(String kid) {
		this.kid = kid;
	}

	/**
	 * The algorithm used to sign the token. For Sign in with Apple, use ES256.
	 */
	public String getAlg() {
		return alg;
	}

	public void setAlg(String alg) {
		this.alg = alg;
	}

}
