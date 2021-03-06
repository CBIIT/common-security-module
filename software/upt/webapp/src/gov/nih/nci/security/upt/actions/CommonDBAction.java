/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.upt.actions;

/**
 *
 *<!-- LICENSE_TEXT_START -->
 *
 *The NCICB Common Security Module's User Provisioning Tool (UPT) Software License,
 *Version 3.0 Copyright 2004-2005 Ekagra Software Technologies Limited ('Ekagra')
 *
 *Copyright Notice.  The software subject to this notice and license includes both
 *human readable source code form and machine readable, binary, object code form
 *(the 'UPT Software').  The UPT Software was developed in conjunction with the
 *National Cancer Institute ('NCI') by NCI employees and employees of Ekagra.  To
 *the extent government employees are authors, any rights in such works shall be
 *subject to Title 17 of the United States Code, section 105.
 *
 *This UPT Software License (the 'License') is between NCI and You.  'You (or
 *'Your') shall mean a person or an entity, and all other entities that control,
 *are controlled by, or are under common control with the entity.  'Control' for
 *purposes of this definition means (i) the direct or indirect power to cause the
 *direction or management of such entity, whether by contract or otherwise, or
 *(ii) ownership of fifty percent (50%) or more of the outstanding shares, or
 *(iii) beneficial ownership of such entity.
 *
 *This License is granted provided that You agree to the conditions described
 *below.  NCI grants You a non-exclusive, worldwide, perpetual, fully-paid-up,
 *no-charge, irrevocable, transferable and royalty-free right and license in its
 *rights in the UPT Software to (i) use, install, access, operate, execute, copy,
 *modify, translate, market, publicly display, publicly perform, and prepare
 *derivative works of the UPT Software; (ii) distribute and have distributed to
 *and by third parties the UPT Software and any modifications and derivative works
 *thereof; and (iii) sublicense the foregoing rights set out in (i) and (ii) to
 *third parties, including the right to license such rights to further third
 *parties.  For sake of clarity, and not by way of limitation, NCI shall have no
 *right of accounting or right of payment from You or Your sublicensees for the
 *rights granted under this License.  This License is granted at no charge to You.
 *
 *1.	Your redistributions of the source code for the Software must retain the
 *above copyright notice, this list of conditions and the disclaimer and
 *limitation of liability of Article 6 below.  Your redistributions in object code
 *form must reproduce the above copyright notice, this list of conditions and the
 *disclaimer of Article 6 in the documentation and/or other materials provided
 *with the distribution, if any.
 *2.	Your end-user documentation included with the redistribution, if any, must
 *include the following acknowledgment: 'This product includes software developed
 *by Ekagra and the National Cancer Institute.'  If You do not include such
 *end-user documentation, You shall include this acknowledgment in the Software
 *itself, wherever such third-party acknowledgments normally appear.
 *
 *3.	You may not use the names 'The National Cancer Institute', 'NCI' 'Ekagra
 *Software Technologies Limited' and 'Ekagra' to endorse or promote products
 *derived from this Software.  This License does not authorize You to use any
 *trademarks, service marks, trade names, logos or product names of either NCI or
 *Ekagra, except as required to comply with the terms of this License.
 *
 *4.	For sake of clarity, and not by way of limitation, You may incorporate this
 *Software into Your proprietary programs and into any third party proprietary
 *programs.  However, if You incorporate the Software into third party proprietary
 *programs, You agree that You are solely responsible for obtaining any permission
 *from such third parties required to incorporate the Software into such third
 *party proprietary programs and for informing Your sublicensees, including
 *without limitation Your end-users, of their obligation to secure any required
 *permissions from such third parties before incorporating the Software into such
 *third party proprietary software programs.  In the event that You fail to obtain
 *such permissions, You agree to indemnify NCI for any claims against NCI by such
 *third parties, except to the extent prohibited by law, resulting from Your
 *failure to obtain such permissions.
 *
 *5.	For sake of clarity, and not by way of limitation, You may add Your own
 *copyright statement to Your modifications and to the derivative works, and You
 *may provide additional or different license terms and conditions in Your
 *sublicenses of modifications of the Software, or any derivative works of the
 *Software as a whole, provided Your use, reproduction, and distribution of the
 *Work otherwise complies with the conditions stated in this License.
 *
 *6.	THIS SOFTWARE IS PROVIDED 'AS IS,' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 *(INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 *NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE) ARE DISCLAIMED.  IN NO
 *EVENT SHALL THE NATIONAL CANCER INSTITUTE, EKAGRA, OR THEIR AFFILIATES BE LIABLE
 *FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *<!-- LICENSE_TEXT_END -->
 *
 */



import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import gov.nih.nci.logging.api.user.UserInfoHelper;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.upt.constants.DisplayConstants;
import gov.nih.nci.security.upt.constants.ForwardConstants;
import gov.nih.nci.security.upt.forms.AppUserForm;
import gov.nih.nci.security.upt.forms.BaseDBForm;
import gov.nih.nci.security.upt.forms.LoginForm;
import gov.nih.nci.security.upt.util.JDBCHelper;
import gov.nih.nci.security.upt.viewobjects.SearchResult;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.dispatcher.SessionMap;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.interceptor.SessionAware;
import org.apache.struts2.util.ServletContextAware;

import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;

/**
 * @author Kunal Modi (Ekagra Software Technologies Ltd.)
 *
 *
 */
public class CommonDBAction extends ActionSupport implements ServletContextAware 
{
	private static final Logger logDB = Logger.getLogger(CommonDBAction.class);

	protected ServletContext servletContext;
	

	public void setServletContext(ServletContext arg0) {
		this.servletContext = arg0;
	}

	public String loadHome(BaseDBForm form) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+form.getFormName()+"|loadHome|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}

		session.removeAttribute(DisplayConstants.CURRENT_ACTION);
		session.removeAttribute(DisplayConstants.CURRENT_FORM);
		session.removeAttribute(DisplayConstants.SEARCH_RESULT);
		session.removeAttribute(DisplayConstants.CREATE_WORKFLOW);

		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+form.getFormName()+"|loadHome|Success|Load the Home Page||");

		return ForwardConstants.LOAD_HOME_SUCCESS;
	}

	public String loadAdd(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|loadAdd|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}

		baseDBForm.resetForm();

		session.setAttribute(DisplayConstants.CURRENT_ACTION, DisplayConstants.ADD);
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
		session.removeAttribute(DisplayConstants.SEARCH_RESULT);
		session.setAttribute(DisplayConstants.CREATE_WORKFLOW,DisplayConstants.CREATE_WORKFLOW);

		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|loadAdd|Success|Loading the Add Page||");
		return ForwardConstants.LOAD_ADD_SUCCESS;
	}

	public String loadSearch(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|loadSearch|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}

		baseDBForm.resetForm();

		session.setAttribute(DisplayConstants.CURRENT_ACTION, DisplayConstants.SEARCH);
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);

		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|loadSearch|Success|Loading the Search Page||");
		return ForwardConstants.LOAD_SEARCH_SUCCESS;
	}

	public String loadSearchResult(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|loadSearchResult|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}

		if(session.getAttribute(DisplayConstants.CREATE_WORKFLOW)!=null){
			//session.removeAttribute(DisplayConstants.CREATE_WORKFLOW);
			session.removeAttribute(DisplayConstants.SEARCH_RESULT);
			session.removeAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT);
			return ForwardConstants.LOAD_HOME_SUCCESS;
		}else{
				if(session.getAttribute(DisplayConstants.SEARCH_RESULT) == null && session.getAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT) != null){
					session.setAttribute(DisplayConstants.SEARCH_RESULT,session.getAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT));
					//session.removeAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT);
				}
			}


		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|loadSearchResult|Success|Loading the Search Result Page||");
		return ForwardConstants.LOAD_SEARCH_RESULT_SUCCESS;
	}

	/**
	* Added this method to handle pre-popup search results.
	*/

	public String loadOriginalSearchResult(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|loadSearchResult|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}

		if(session.getAttribute(DisplayConstants.CREATE_WORKFLOW)!=null){
			session.removeAttribute(DisplayConstants.CREATE_WORKFLOW);
			//session.removeAttribute(DisplayConstants.SEARCH_RESULT);
			return ForwardConstants.LOAD_HOME_SUCCESS;
		}else{
			if(session.getAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT) != null){
				session.setAttribute(DisplayConstants.SEARCH_RESULT,session.getAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT));
				session.removeAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT);
			}
		}


		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|loadSearchResult|Success|Loading the Search Result Page||");
		return ForwardConstants.LOAD_SEARCH_RESULT_SUCCESS;
	}



	public String create(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|create|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		UserInfoHelper.setUserInfo(((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId(), session.getId());
		try
		{
			List<String> errors = baseDBForm.validate();
			if(errors != null && errors.size() > 0)
			{
				for(String error: errors)
				{
					addActionError(error);
				}
				session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
				if (logDB.isDebugEnabled())
					logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
						"|"+baseDBForm.getFormName()+"|create|Failure|Error validating the "+baseDBForm.getFormName()+" object|"
						+baseDBForm.toString()+"|");
				return "input";
			}
			UserProvisioningManager userProvisioningManager = (UserProvisioningManager)(request.getSession()).getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
			baseDBForm.setRequest(request);
			baseDBForm.buildDBObject(userProvisioningManager);
			addActionMessage("Add Successful");
		}
		catch (CSException cse)
		{
			addActionError(org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|create|Failure|Error Adding the "+baseDBForm.getFormName()+" object|"
					+baseDBForm.toString()+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+baseDBForm.getFormName()+"|create|Success|Adding a  new "+baseDBForm.getFormName()+" object|"
				+baseDBForm.toString()+"|");
		return ForwardConstants.CREATE_SUCCESS;
	}


	public String read(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();
		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|read|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		if (baseDBForm.getPrimaryId() == null || baseDBForm.getPrimaryId().equalsIgnoreCase(""))
		{
			addActionError( "A record needs to be selected first to view details" );
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|read|Failure|No Primary Id for "+baseDBForm.getFormName()+" object||");
			return ForwardConstants.READ_FAILURE;
		}
		try
		{
			UserProvisioningManager userProvisioningManager = (UserProvisioningManager)(request.getSession()).getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
			baseDBForm.setRequest(request);
			baseDBForm.buildDisplayForm(userProvisioningManager);
		}
		catch (CSException cse)
		{
			addActionError(org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|read|Failure|Error Reading the "+baseDBForm.getFormName()+" object|"
					+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+baseDBForm.getFormName()+"|read|Success|Success reading "+baseDBForm.getFormName()+" object|"
				+"|");

		return ForwardConstants.READ_SUCCESS;
	}

	public String update(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|update|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		UserInfoHelper.setUserInfo(((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId(), session.getId());
		try
		{
			List<String> errors = baseDBForm.validate();
			if(errors != null && errors.size() > 0)
			{
				for(String error : errors)
					addActionError(error);
				session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
				if (logDB.isDebugEnabled())
					logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
						"|"+baseDBForm.getFormName()+"|update|Failure|Error validating the "+baseDBForm.getFormName()+" object|"
						+"|");
				return "input";
			}
			UserProvisioningManager userProvisioningManager = (UserProvisioningManager)(request.getSession()).getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
			baseDBForm.setRequest(request);
			baseDBForm.buildDBObject(userProvisioningManager);
			addActionMessage("Update Successful");
		}
		catch (CSException cse)
		{
			addActionError( org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|update|Failure|Error Updating the "+baseDBForm.getFormName()+" object|"
					+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);

		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+baseDBForm.getFormName()+"|update|Success|Updating existing "+baseDBForm.getFormName()+" object|"
				+"|");
		return ForwardConstants.UPDATE_SUCCESS;
	}

	public String delete(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|delete|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		UserInfoHelper.setUserInfo(((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId(), session.getId());
		try
		{
			UserProvisioningManager userProvisioningManager = (UserProvisioningManager)(request.getSession()).getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
			baseDBForm.setRequest(request);
			baseDBForm.buildDisplayForm(userProvisioningManager);
			baseDBForm.removeDBObject(userProvisioningManager);
			addActionMessage("Delete Successful");
		}
		catch (CSException cse)
		{
			addActionError(org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|delete|Failure|Error Deleting the "+baseDBForm.getFormName()+" object|"
					+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+baseDBForm.getFormName()+"|delete|Success|Success Deleting "+baseDBForm.getFormName()+" object|"
				+"|");
		return ForwardConstants.DELETE_SUCCESS;
	}

	public String search(BaseDBForm baseDBForm) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+baseDBForm.getFormName()+"|search|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		UserInfoHelper.setUserInfo(((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId(), session.getId());
		try
		{
			UserProvisioningManager userProvisioningManager = (UserProvisioningManager)(request.getSession()).getAttribute(DisplayConstants.USER_PROVISIONING_MANAGER);
			baseDBForm.setRequest(request);
			SearchResult searchResult = baseDBForm.searchObjects(userProvisioningManager);
			if ( searchResult.getSearchResultObjects() == null || searchResult.getSearchResultObjects().isEmpty())
			{
				addActionError("The search criteria returned zero results");
				if (logDB.isDebugEnabled())
					logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
						"|"+baseDBForm.getFormName()+"|search|Failure|No Records found for "+baseDBForm.getFormName()+" object|"
						+"|");
				baseDBForm.resetForm();
				return ForwardConstants.SEARCH_FAILURE;
			}
			if (searchResult.getSearchResultMessage() != null && !(searchResult.getSearchResultMessage().trim().equalsIgnoreCase("")))
			{
				addActionMessage(searchResult.getSearchResultMessage());
			}


			session.setAttribute(DisplayConstants.SEARCH_RESULT, null);
			session.setAttribute(DisplayConstants.CREATE_WORKFLOW, null);
			session.setAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT, null);
			session.setAttribute(DisplayConstants.CURRENT_FORM, null);
			if(session.getAttribute(DisplayConstants.SEARCH_RESULT)!=null){
				String str = (String) session.getAttribute(DisplayConstants.CREATE_WORKFLOW);
				if(session.getAttribute(DisplayConstants.CREATE_WORKFLOW)==null){
						if(session.getAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT)==null){
							session.setAttribute(DisplayConstants.ORIGINAL_SEARCH_RESULT, session.getAttribute(DisplayConstants.SEARCH_RESULT) );
						}
				}
			}
			session.setAttribute(DisplayConstants.SEARCH_RESULT, searchResult);
		}
		catch (CSException cse)
		{
			addActionError(org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+baseDBForm.getFormName()+"|search|Failure|Error Searching the "+baseDBForm.getFormName()+" object|"
					+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, baseDBForm);
		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+baseDBForm.getFormName()+"|search|Success|Success in searching "+baseDBForm.getFormName()+" object|"
				+"|");
		return ForwardConstants.SEARCH_SUCCESS;
	}

	public String testConnection(BaseDBForm form) throws Exception
	{
		HttpServletRequest request = ServletActionContext.getRequest();
		HttpSession session = request.getSession();

		if (session.isNew() || (session.getAttribute(DisplayConstants.LOGIN_OBJECT) == null)) {
			if (logDB.isDebugEnabled())
				logDB.debug("||"+form.getFormName()+"|Test Connection|Failure|No Session or User Object Forwarding to the Login Page||");
			return ForwardConstants.LOGIN_PAGE;
		}
		UserInfoHelper.setUserInfo(((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId(), session.getId());
		try
		{
			List<String> errors = form.validate();
			if(errors != null && errors.size() > 0)
			{
				for(String error : errors)
					addActionError(error);
				session.setAttribute(DisplayConstants.CURRENT_FORM, form);
				if (logDB.isDebugEnabled())
					logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
						"|"+form.getFormName()+"|Test Connection|Failure|Error testing Aplication Database Connection"
						+"|");
				return "input";
			}

			// Test JDBC Database Connection Properties.
			//String message = JDBCHelper.testConnectionHibernate(baseDBForm);
			String message = JDBCHelper.testConnectionJDBC(form);

			//
			addActionMessage(message);
		}
		catch (CSException cse)
		{
			addActionError(org.apache.commons.lang.StringEscapeUtils.escapeHtml(cse.getMessage()));
			if (logDB.isDebugEnabled())
				logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
					"|"+form.getFormName()+"|Test Connection|Failure|Error Testing Application Database Connection."
					+"|"+ cse.getMessage());
		}
		session.setAttribute(DisplayConstants.CURRENT_FORM, form);

		if (logDB.isDebugEnabled())
			logDB.debug(session.getId()+"|"+((LoginForm)session.getAttribute(DisplayConstants.LOGIN_OBJECT)).getLoginId()+
				"|"+form.getFormName()+"|Test Connection|Success|Testing Application Database connection."
				+"|");
		return ForwardConstants.UPDATE_SUCCESS;
	}

}
