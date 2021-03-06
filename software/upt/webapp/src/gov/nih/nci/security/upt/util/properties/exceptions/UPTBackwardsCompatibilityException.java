/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.upt.util.properties.exceptions;


/**
 * 
 * 
 * 
 * @author Vijay Parmar
 */
public class UPTBackwardsCompatibilityException extends Exception
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * Default Constructor
	 */
	public UPTBackwardsCompatibilityException() {
		super();
		
	}
	/**
	 * This constructor creates the {@link Exception} classed with the passed message
	 * @param message the error message describing the exception
	 */
	public UPTBackwardsCompatibilityException(String message) {
		super(message);
		
	}
	/**
	 * This constructor creates the {@link Exception} classed with the passed message and also stores the 
	 * actual {@link Throwable} object which caused the error
	 * @param message the error message describing the exception
	 * @param cause the actual exception which occured and caused this exception
	 */
	public UPTBackwardsCompatibilityException(String message, Throwable cause) {
		super(message, cause);
		
	}
	/**
	 * This constructor creates the {@link Exception} classed the actual {@link Throwable} object which caused the error
	 * @param cause the actual exception which occured and caused this exception
	 */
	public UPTBackwardsCompatibilityException(Throwable cause) {
		super(cause);
		
	}
}
