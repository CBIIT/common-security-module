<%--L
   Copyright Ekagra Software Technologies Ltd.
   Copyright SAIC, SAIC-Frederick

   Distributed under the OSI-approved BSD 3-Clause License.
   See http://ncip.github.com/common-security-module/LICENSE.txt for details.
L--%>

<%@ taglib uri="/struts-tags" prefix="s" %>

<%@ taglib uri="/WEB-INF/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page import="gov.nih.nci.security.upt.constants.*"%>
<%@ page import="gov.nih.nci.security.authorization.domainobjects.*"%>
<%@ page import="gov.nih.nci.security.constants.Constants"%>
<script> 
    <!--
    	function setAndSubmit(target)
    	{
    		if (target == "read")
    		{
	    		document.UserForm.operation.value=target;
	    		document.UserForm.submit();
    		}
    		else
    		{		
	    		var len = document.UserForm.associatedIds.length;
	    		for (i=0 ; i < len ; i++)
	    		{
	    			document.UserForm.associatedIds[i].selected = true;
	    		}
	    		document.UserForm.operation.value=target;
	    		document.UserForm.submit();
			}
	    }    	
    	// selSwitch functions

		function selSwitch(btn)
		{
		   var i= btnType = 0;
		   var isavailableIds = doIt = false;
		
		   if (btn.value == "Assign" || btn.value == "Deassign") 
		      btnType = 1;
		   else if (btn.value == "Assign All" || btn.value == "Deassign All") 
		      btnType = 2;
		   else
		      btnType = 3;
		
	      isavailableIds = (btn.value.indexOf('Assign') != -1) ? true : false;     
	
	      with ( ((isavailableIds)? document.dummyForm.availableIds: document.UserForm.associatedIds) )
	      {
	         for (i = 0; i < length; i++)
	         {
	            doIt = false;
	            if (btnType == 1)
	            { 
	               if(options[i].selected) doIt = true;
	            }
	            else if (btnType == 2)
	            {
	               doIt = true;
	            } 
	            else 
	               if (!options[i].selected) doIt = true;
	             
	            if (doIt)
	            {
	               with (options[i])
	               {
	                  if (isavailableIds)
	                     document.UserForm.associatedIds.options[document.UserForm.associatedIds.length] = new Option( text, value );
	                  else
	                     document.dummyForm.availableIds.options[document.dummyForm.availableIds.length] = new Option( text, value );
	               } 
	               options[i] = null;
	               i--;
	            } 
	         } // end for loop
	         if (options[0] != null)
	            options[0].selected = true;
	      } // end with isavailableIds
		}   
		
function skipNavigation()
{
	document.getElementById("userAssoc").focus();
	window.location.hash="userAssoc";
	document.getElementById("ncilink").tabIndex = -1;
	document.getElementById("nihlink").tabIndex = -1;
	document.getElementById("skipmenu").tabIndex = -1;
	
	document.getElementById("homeLink").tabIndex = -1;
	if(document.getElementById("adminhomeLink"))
		document.getElementById("adminhomeLink").tabIndex = -1;
		
	document.getElementById("menuHome").tabIndex = -1;
	document.getElementById("menuUser").tabIndex = -1;
	document.getElementById("menuPE").tabIndex = -1;
	document.getElementById("menuPrivilege").tabIndex = -1;
	document.getElementById("menuGroup").tabIndex = -1;
	document.getElementById("menuPG").tabIndex = -1;
	document.getElementById("menuRole").tabIndex = -1;
	document.getElementById("menuInstance").tabIndex = -1;
	document.getElementById("menulogout").tabIndex = -1;
} 	
		
		// -->
    </script>

<table cellpadding="0" cellspacing="0" border="0" class="contentPage" width="100%" height="100%">
	<tr>
		<td valign="top" width="100%">
		<table width="100%" cellpadding="0" cellspacing="0" border="0" class="contentBegins">
			<tr>
				<td colspan="3">
					<h2><a id="userAssoc"></a>User and Groups Association</h2>
				</td>
			</tr>
			<s:set var="userForm" value="#session.CURRENT_FORM"/>
			<s:if test='#!userForm.userLoginName.equals(""))'>
			<tr>
				<td>
					<table cellpadding="3" cellspacing="0" border="0" width="90%" align="center">
						<tr>
							<td class="formTitle" height="20" colspan="2">SELECTED USER</td>
						</tr>
						<tr class="dataRowDark">
							<td class="formRequiredLabel" width="40%" scope="row"><label for="userLoginName">User Login Name</label></td>
							<td class="formField" width="60%"><s:property value="#userForm.userLoginName"/></td>
						</tr>
					</table>
				</td>
			</tr>
			</s:if>
			<tr>
				<td valign="top" align="center" width="80%"><!-- sidebar begins -->
				<table cellpadding="3" cellspacing="10" border="0" height="100%" width="100%">
					<tr>
						<td class="infoMessage" colspan="3">
							<s:if test="hasActionMessages()">
							      <s:actionmessage/>
							</s:if>
		  				</td>
					</tr>
					<tr>
						<td class="formMessage" colspan="3">Assign or Deassign multiple <b>Groups</b> 
						for the selected <b>User</b>. To remove the complete association Deassign all the <b>Groups</b>.</td>
					</tr>
					
					<!-- large table starts -->
					
					<tr>
					<!-- cell begins-->
					<td width="100%">
					<table width="100%">
					<!-- ROW 1 begins -->
					<tr>	
					
					<!-- first section -->
					
					
					<td width="100%" valign="top">
					<form name="dummyForm">
					<table cellpadding="0" cellspacing="0" border="0" width="100%" class="sidebarSection">
						<tr>

							<td class="sidebarTitle" height="20">AVAILABLE GROUPS</td>
						</tr>
						<tr>
						<td class="formField" align="center">
							<select name="availableIds" multiple style="width:100%;" size="6">
							<s:iterator value="#request.AVAILABLE_SET" var="group">
								<option value='<s:property value="#group.groupId"/>'><s:property value="#group.groupName"/></option>
							</s:iterator>
	                    	</select>
	                    </td>
						</tr>
					</table>
					</form>
					</td>
					
					
					</tr>
					<!-- end first, start second -->
					<tr>
					
					<!-- extra code -->
							<td align="center" width="100%">
							<table width="220">
							<tr>
							<!-- -->
					<s:if test="#session.UPDATE_UPT_USER_OPERATION != null">
						<td align="center">
							<input type="button" value="Assign" style="width:75px;" onclick="selSwitch(this);">
						</td>
						<td align="center">
							<input type="button" value="Deassign" style="width:75px;" onclick="selSwitch(this);">
						</td>
					</s:if>
					<s:if test="#session.UPDATE_UPT_USER_OPERATION == null">
						<td align="center">
							<input type="button" value="Assign" style="width:75px;" disabled="disabled" />
						</td>
						<td align="center">
							<input type="button" value="Deassign" style="width:75px;" disabled="disabled" >
						</td>
					</s:if>
					
					<!-- extra code -->
							</tr>
							</table>
							</td>
							<!-- -->	
					
					
					</tr>
					<!-- end second, start third -->
					<tr>
					
					
					
					<td width="100%" valign="top">
					<s:form name="UserForm" action="UserDBOperation" theme="simple">
					<s:hidden name="operation" value="read"/>
					<s:set var="userId" value="#userForm.getUserId()"/>
					<s:hidden name="userForm.userId" value="%{userId}"/>

					<input type="hidden" name="<csrf:token-name/>" value="<csrf:token-value uri='/UserDBOperation'/>"/>
					<table cellpadding="0" cellspacing="0" border="0" width="100%" class="sidebarSection">
						<tr>

							<td class="sidebarTitle" height="20">ASSIGNED GROUPS</td>
						</tr>
						<tr>
						<td class="formField" align="center">
							<select name="associatedIds" multiple style="width:100%;" size="6">
							<s:iterator value="#request.ASSIGNED_SET" var="group2">
								<option value='<s:property value="#group2.groupId"/>'><s:property value="#group2.groupName"/></option>
							</s:iterator>
				                    	</select>
	                    </td>
						</tr>
					</table>
					</td>
					
					
					</tr>
					<!-- end third section -->
					
					
					<tr>
				<td align="right" class="actionSection"><!-- action buttons begins -->
				<table cellpadding="4" cellspacing="0" border="0">
					<tr>
						<s:if test="#session.UPDATE_UPT_USER_OPERATION != null">
							<td><s:submit class="actionButton" onclick="setAndSubmit('setAssociation');" value="Update Association"/></td>
						</s:if>
						<s:if test="#session.UPDATE_UPT_USER_OPERATION == null">
							<td><s:submit class="actionButton" disabled="disabled" value="Update Association"/></td>
						</s:if>
						<td><s:submit style="actionButton" onclick="setAndSubmit('read');" value="Back"/></td>						
					</tr>
				</table>
				</td>				
			</tr>
					
					
					<!--close up big table-->
					</table>
					</td>
					
					</tr>
				</table>
			</tr>
			
			</s:form>
		</table>
		</td>
	</tr>
</table>


