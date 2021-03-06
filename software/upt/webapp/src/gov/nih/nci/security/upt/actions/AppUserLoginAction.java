/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.upt.actions;


import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.upt.constants.DisplayConstants;
import gov.nih.nci.security.upt.forms.AppUserForm;
import gov.nih.nci.security.upt.forms.LoginForm;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;



public class AppUserLoginAction extends CommonDBAction
{
	private static final Logger log = Logger.getLogger(AppUserLoginAction.class);
	private AppUserForm userForm;
	
	public void setUserForm(AppUserForm userForm)
	{
		this.userForm = userForm;
	}
	
	public AppUserForm getUserForm()
	{
		return userForm;
	}
	
	@SuppressWarnings("unchecked")
	public String execute() throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();
		UserProvisioningManager userProvisioningManager = (UserProvisioningManager)session.getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
		
		if (userForm != null && userForm.getOperation() != null && userForm.getOperation().equalsIgnoreCase("update"))
		{
			update(userForm);
			userForm.setOperation("");
			return read(userForm);
		}
		else
		{
			userForm = new AppUserForm();
			String loginId = ((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId();
			User user = userProvisioningManager.getUser(loginId);

			userForm.setUserId(Long.toString(user.getUserId()));

			return read(userForm);
		}						
	}
}
