<%--L
   Copyright Ekagra Software Technologies Ltd.
   Copyright SAIC, SAIC-Frederick

   Distributed under the OSI-approved BSD 3-Clause License.
   See http://ncip.github.com/common-security-module/LICENSE.txt for details.
L--%>

<%@ taglib uri="/tags/struts-html" prefix="html"%>
<%@ taglib uri="/tags/struts-logic" prefix="logic"%>

<%@ page import="gov.nih.nci.security.upt.constants.*"%>

<script>
  <!--
    	
//-->

</script>


	<table summary="" cellpadding="0" cellspacing="0" border="0"
		class="contentPage" width="100%" height="100%">
		<tr>
			<td valign="top">
			<table cellpadding="0" cellspacing="0" border="0"
				class="contentBegins">
				<tr>
					<td colspan="3">

					<h2>User Provisioning Tool</h2>

					<h3>Welcome!</h3>

					<p>Welcome to the User Provisioning Tool. You may begin by clicking
					on any menu option above, or you can follow our Recommended
					Workflow outlined below.<br>This diagram shows how UPT security
					objects are related.  Roll over objects to learn more. </p>
					</td>
					<td width="30%">&nbsp;</td>
					<tr><td colspan="4">&nbsp;</td></tr>
				</tr>




				<!--
				<!-- diagram -->

				<tr>
					<td colspan="2" width="50%">

					<table cellspacing="0" cellpadding="0">
						<tr>
							<td height="50%">
							<table width="50%" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.USER_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('user','','images/Users.gif',1)"><img
										name="user" border="0" src="images/Users2.gif" width="98"
										height="50" alt="A User is someone that requires access to your application. Users can become part of a Group, and can have an associated Protection Group and Roles."
										Title="A User is someone that requires access to your application. Users can become part of a Group, and can have an associated Protection Group and Roles."></a></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.PROTECTION_ELEMENT_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('PEs','','images/protectionelements.gif',1)"><img
										name="PEs" border="0" src="images/protectionelements2.gif"
										width="98" height="50" alt="A Protection Element is any entity (typically data) that has controlled access. Examples include Social Security Number, City, and Salary."
										Title="A Protection Element is any entity (typically data) that has controlled access. Examples include Social Security Number, City, and Salary."></a></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.PRIVILEGE_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('priv','','images/privileges.gif',1)"><img
										name="priv" border="0" src="images/privileges2.gif" width="98"
										height="50" alt="A Privilege refers to any operation performed upon data. Examples include DELETE or UPDATE."
										Title="A Privilege refers to any operation performed upon data. Examples include DELETE or UPDATE."></a></td>
								</tr>

								<tr>
									<td width="100%" height="50"><img src="images/create.gif"
										width="98" height="50"></td>
								</tr>
							</table>
							</td>
							<td height="100%">
							<table
								background="<html:rewrite href="images/dotted_line1.gif"/>"
								width="100%" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td height="100"><img src="images/elbow.gif" width="98"
										height="100"></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>

								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
							</table>
							</td>
							<td height="100%">
							<table width="100%" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.GROUP_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('group','','images/groups.gif',1)"><img
										name="group" border="0" src="images/groups2.gif" width="98"
										height="50" alt="A Group is a collection of application users. By combining users into a Group, it becomes easier to manage their collective roles and access rights in your application."
										title="A Group is a collection of application users. By combining users into a Group, it becomes easier to manage their collective roles and access rights in your application."></a></td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.PROTECTION_GROUP_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('pgs','','images/protectiongroups.gif',1)"><img
										name="pgs" border="0" src="images/protectiongroups2.gif"
										width="98" height="50" alt="A Protection Group is a collection of application Protection Elements. By combining Protection Elements into a Protection Group, it becomes easier to associate Users and Groups with rights to a particular data set. Examples include Address and Personal Information."
										title="A Protection Group is a collection of application Protection Elements. By combining Protection Elements into a Protection Group, it becomes easier to associate Users and Groups with rights to a particular data set. Examples include Address and Personal Information."></a></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><a
										href="javascript: set('<%=DisplayConstants.ROLE_ID%>')"
										onMouseOut="MM_swapImgRestore()"
										onMouseOver="MM_swapImage('roles','','images/roles.gif',1)"><img
										name="roles" border="0" src="images/roles2.gif" width="98"
										height="50" alt="A Role is a collection of application Privileges. Examples include Record Admin. and EmployeeModify."
										title="A Role is a collection of application Privileges. Examples include Record Admin. and EmployeeModify."></a></td>
								</tr>

								<tr>
									<td width="100%" height="50"><img src="images/assign.gif"
										width="98" height="50"></td>
								</tr>
							</table>
							</td>
							<td height="100%">
							<table
								background="<html:rewrite href="images/dotted_line2.gif"/>"
								width="100%" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>
								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
								<tr>
									<td width="100%" height="50"><img
										src="images/horizontal_line.gif" width="98" height="50"></td>
								</tr>

								<tr>
									<td width="100%" height="50">&nbsp;</td>
								</tr>
							</table>
							</td>
							<td valign="top" height="100%">
							<table width="100%" border="0" cellspacing="0" cellpadding="0">
								<tr>
									<td valign="top" height="100%"><img src="images/assoc_block2.gif" width="98" height="300" alt="Each User assumes Roles for Protection Groups.  For example, User John has a Role EmployeeModify for all elements in the Address Protection Group. Assign PGs and Roles from the User or Group sections of the UPT." /></td>
								</tr>

								<tr>
									<td width="100%" height="50"><img src="images/associate.gif"
										width="98" height="50"></td>
								</tr>
							</table>
							</td>
						</tr>
					</table>

					</td>
					
					<td colspan="2" width="50%">&nbsp;</td>
				</tr>






				<tr class="home">
					<td class="home" colspan="4">&nbsp;</td>
				</tr>




				<!-- workflow begins-->
				<tr>

					<td colspan="4">
					<table cellpadding="0" cellspacing="0" border="0"
						class="contentBegins">
						<!--recommended flow-->
						<tr class="home">
							<td class="home" colspan="3">
							<h3>Recommended Workflow</h3>
							<p>When initially adding an application, we recommend the
							following steps:</p>

							</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>

						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>

						<tr class="home">
							<td class="home" colspan="3">1. Create base objects - <b>Users</b> and
							<b>Protection</b> <b>Elements</b>. <b>CSM Standard Privileges</b> are provided.</td>
							<td class="home" width="25%">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" colspan="3" align="center">
							<div align="left">2. Create collections of these objects.</div>
							</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">&nbsp;</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						<!-- Section A -->
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Create <b>Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
				
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Assign <b>Users</b> to <b>Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
						<!-- Section B -->
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Create <b>Protection Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Assign <b>Protection Elements</b> to
							<b>Protection Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
						<!-- Section C -->
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Create <b>Roles</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Assign <b>Privileges</b> to <b>Roles</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
			
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" colspan="3">3. Associate rights with <b>Users</b>
							and <b>Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
						<!-- Step 2 A -->
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Assign a <b>Protection Group</b> and
							<b>Roles</b> to <b>Users</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">&nbsp;</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" width="5%" align="center">&nbsp;</td>
							<td class="home" colspan="2">Assign a <b>Protection Group</b> and
							<b>Roles</b> to <b>Groups</b>.</td>
							<td class="home" width="27%">&nbsp;</td>
						</tr>
						
						<tr class="home">
							<td class="home" colspan="4">&nbsp;</td>
						</tr>
					</table>
				</td>
				</tr>
				<!-- workflow ends, association begins -->


				
			</table>
			</td>
		</tr>
	</table>

