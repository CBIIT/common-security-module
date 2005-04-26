package gov.nih.nci.logging.struts;

import org.apache.struts.validator.ValidatorForm;
import org.apache.struts.action.*;

/**
 * 
 * Form for passing authentication creditals.
 * @author Brian Husted
 *
 */
public class LoginForm extends ValidatorForm {

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



