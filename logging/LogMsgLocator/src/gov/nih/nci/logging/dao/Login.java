package gov.nih.nci.logging.dao;

import java.io.*;

/**
 * ean class for storing user credentials.
 * 
 * @author Brian Husted
 */
public class Login implements Serializable {

 	private String username;
 	private String password;



	/**
	 * @return Returns the password.
	 */
	public String getPassword() {
		return password;
	}
	/**
	 * @param password The password to set.
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	/**
	 * @return Returns the username.
	 */
	public String getUsername() {
		return username;
	}
	/**
	 * @param username The username to set.
	 */
	public void setUsername(String username) {
		this.username = username;
	}
}