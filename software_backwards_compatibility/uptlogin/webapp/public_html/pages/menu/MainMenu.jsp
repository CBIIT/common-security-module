<%--L
   Copyright Ekagra Software Technologies Ltd.
   Copyright SAIC, SAIC-Frederick

   Distributed under the OSI-approved BSD 3-Clause License.
   See http://ncip.github.com/common-security-module/LICENSE.txt for details.
L--%>

<%@ taglib uri="http://jakarta.apache.org/struts/tags-bean"
	prefix="bean"%>
<%@ taglib uri="http://jakarta.apache.org/struts/tags-html"
	prefix="html"%>
<%@ taglib uri="http://jakarta.apache.org/struts/tags-logic"
	prefix="logic"%>
<%@ taglib uri="http://jakarta.apache.org/struts/tags-tiles"
	prefix="tiles"%>
<%@ taglib uri="http://jakarta.apache.org/struts/tags-template"
	prefix="template"%>
<%@ taglib uri="http://jakarta.apache.org/struts/tags-nested"
	prefix="nested"%>

<%@ page import="gov.nih.nci.security.loginapp.constants.*"%>

<script>
  <!--
    	function set(tableId)
    	{
    		document.MenuForm.tableId.value=tableId;
    		document.MenuForm.submit();
    	}
    	
    	  
function MM_swapImgRestore() { //v3.0
  var i,x,a=document.MM_sr; for(i=0;a&&i<a.length&&(x=a[i])&&x.oSrc;i++) x.src=x.oSrc;
}

function MM_preloadImages() { //v3.0
  var d=document; if(d.images){ if(!d.MM_p) d.MM_p=new Array();
    var i,j=d.MM_p.length,a=MM_preloadImages.arguments; for(i=0; i<a.length; i++)
    if (a[i].indexOf("#")!=0){ d.MM_p[j]=new Image; d.MM_p[j++].src=a[i];}}
}

function MM_findObj(n, d) { //v4.0
  var p,i,x;  if(!d) d=document; if((p=n.indexOf("?"))>0&&parent.frames.length) {
    d=parent.frames[n.substring(p+1)].document; n=n.substring(0,p);}
  if(!(x=d[n])&&d.all) x=d.all[n]; for (i=0;!x&&i<d.forms.length;i++) x=d.forms[i][n];
  for(i=0;!x&&d.layers&&i<d.layers.length;i++) x=MM_findObj(n,d.layers[i].document);
  if(!x && document.getElementById) x=document.getElementById(n); return x;
}

function MM_swapImage() { //v3.0
  var i,j=0,x,a=MM_swapImage.arguments; document.MM_sr=new Array; for(i=0;i<(a.length-2);i+=3)
   if ((x=MM_findObj(a[i]))!=null){document.MM_sr[j++]=x; if(!x.oSrc) x.oSrc=x.src; x.src=a[i+2];}
}
    	
    	
   // -->
</script>

<html:form styleId="menuForm" action="<%="/MenuSelection"%>">
	<%
	String tableId;
	try
	{
		tableId = (String)session.getAttribute(DisplayConstants.CURRENT_TABLE_ID);
		if (tableId.equalsIgnoreCase(DisplayConstants.BLANK))
		{
			tableId = DisplayConstants.HOME_ID;
			session.setAttribute(DisplayConstants.CURRENT_TABLE_ID,DisplayConstants.HOME_ID);
		}
	}
	catch (Exception e)
	{
		tableId = DisplayConstants.HOME_ID;
		session.setAttribute(DisplayConstants.CURRENT_TABLE_ID,DisplayConstants.HOME_ID);
	}
	%>
	<html:hidden property="tableId" value="error" />
	<td class="mainMenu" height="20">
	<table summary="" cellpadding="0" cellspacing="0" border="0"
		height="16">
		<logic:present name="<%=DisplayConstants.LOGIN_OBJECT%>">
			<tr	height="16">
				<td  height="16" width="1"><!-- anchor to skip main menu --><a href="#content"><img
					src="images/shim.gif" alt="Skip Menu" width="1" height="1"
					border="0"></a></td>
				<!-- link 1 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.HOME_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.HOME_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.HOME_ID%>')">HOME</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.HOME_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.HOME_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.HOME_ID%>')">HOME</a>
			<%}%>
				<!-- link 1 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 7 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.USER_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.USER_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.USER_ID%>')">USER</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.USER_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.USER_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.USER_ID%>')">USER</a>
				<%}%>
				<!-- link 7 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 4 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.PROTECTION_ELEMENT_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PROTECTION_ELEMENT_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PROTECTION_ELEMENT_ID%>')">PROTECTION
				ELEMENT</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.PROTECTION_ELEMENT_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PROTECTION_ELEMENT_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PROTECTION_ELEMENT_ID%>')">PROTECTION
				ELEMENT</a>
				<%}%>
				<!-- link 4 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 3 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.PRIVILEGE_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PRIVILEGE_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PRIVILEGE_ID%>')">PRIVILEGE</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.PRIVILEGE_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PRIVILEGE_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PRIVILEGE_ID%>')">PRIVILEGE</a>
				<%}%>
				<!-- link 3 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 2 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.GROUP_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.GROUP_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.GROUP_ID%>')">GROUP</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.GROUP_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.GROUP_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.GROUP_ID%>')">GROUP</a>
				<%}%>
				<!-- link 2 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 5 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.PROTECTION_GROUP_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PROTECTION_GROUP_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PROTECTION_GROUP_ID%>')">PROTECTION
				GROUP</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.PROTECTION_GROUP_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.PROTECTION_GROUP_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.PROTECTION_GROUP_ID%>')">PROTECTION
				GROUP</a>
				<%}%>
				<!-- link 5 ends -->
				<td height="16"><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 6 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.ROLE_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.ROLE_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.ROLE_ID%>')">ROLE</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.ROLE_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.ROLE_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.ROLE_ID%>')">ROLE</a>
				<%}%>
				<!-- link 6 ends -->
				<td><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 7 begins -->
				<%if (tableId.equalsIgnoreCase(DisplayConstants.INSTANCE_LEVEL_ID)){%>
				<td height="16" class="mainMenuItemOver"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItemOver'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.INSTANCE_LEVEL_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.INSTANCE_LEVEL_ID%>')">INSTANCE LEVEL</a>
				<%}if (!tableId.equalsIgnoreCase(DisplayConstants.INSTANCE_LEVEL_ID)){%>
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					onclick="javascript: set('<%=DisplayConstants.INSTANCE_LEVEL_ID%>')"><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.INSTANCE_LEVEL_ID%>')">INSTANCE LEVEL</a>
				<%}%>
				<!-- link 7 ends -->
				<td><img src="images/mainMenuSeparator.gif" width="1" height="16"
					/>
				<!-- link 8 begins -->
				<td height="16" class="mainMenuItem"
					onmouseover="changeMenuStyle(this,'mainMenuItemOver'),showCursor()"
					onmouseout="changeMenuStyle(this,'mainMenuItem'),hideCursor()"
					><a
					class="mainMenuLink"
					href="javascript: set('<%=DisplayConstants.LOGOUT_ID%>')">LOG OUT</a>
				<!-- link 8 ends -->
				<td><img src="images/mainMenuSeparator.gif" width="1" height="16"/></td>
			</tr>
		</logic:present>
	</table>
	</td>
</html:form>
