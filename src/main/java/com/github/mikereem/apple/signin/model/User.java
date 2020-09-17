package com.github.mikereem.apple.signin.model;

/**
 * User model.
 * 
 * @author mikereem
 *
 */
public class User {

	private Name name;
	private String email;

	public Name getName() {
		return name;
	}

	public void setName(Name name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

}
