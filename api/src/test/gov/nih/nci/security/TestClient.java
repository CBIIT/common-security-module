/*
 * Created on Dec 9, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

package test.gov.nih.nci.security;


import java.util.Iterator;


import gov.nih.nci.security.SecurityServiceProvider;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.*;



/**
 * 
 * 
 * @author Vinay Kumar (Ekagra Software Technologies Ltd.)
 */
public class TestClient {
    public void testPrivilegeCreate(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("Security");
    	Privilege p = new Privilege();
    	p.setName("Update");
    	p.setDesc("Update Access");
    	try{
    	upm.createPrivilege(p);
    	System.out.println("The returned id is:"+p.getId());
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    public void testPrivilegeDelete(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	
    	try{
    	upm.removePrivilege("10");
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    public void testPrivilegeFind(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	
    	try{
    	Privilege p = upm.getPrivilege("2");
    	System.out.println(p.getName());
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    
    public void testModifyCreate(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	
    	try{
    	 Privilege p = upm.getPrivilege("2");
    	 p.setName("Create");
    	 p.setDesc("Create Access");
    	upm.modifyPrivilege(p);
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    public void testRoleCreate(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("Security");
    	
    	try{
    	  for(int i=3;i<11;i++){
    		Role r = new Role();
        	r.setName("Role_name_"+i);
        	r.setDesc("Role_Desc_"+i);
    	    upm.createRole(r);
    	  }
    	
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    
    public void testRoleDelete(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	
    	try{
    	upm.removeRole("2");
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    
    public void testModifyRole(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	
    	try{
    	Role r = upm.getRoleById("3");
    	r.setDesc("Updated Test Role Desc 2");
    	upm.modifyRole(r);
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    
    public void assignPrivilegeToRoles(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	 String[] privilegeIds = {"2", "3","5"};
    	 //String[] privilegeIds = {"1", "4","6"};
    	 //String[] privilegeIds = {"1", "3","6"};
    	 //String[] privilegeIds = {};
    	 String roleId = "1";
    	 try{
    	 	upm.assignPrivilegesToRole(roleId,privilegeIds);
    	 }catch(Exception ex){
    	 	ex.printStackTrace();
    	 }
    }
    
    public void getPrivileges(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	 
    	 String roleId = "1";
    	 try{
    	 	java.util.Collection result = upm.getPrivileges(roleId);
    	 	Iterator it = result.iterator();
    	 	while(it.hasNext()){
    	 		Privilege p = (Privilege)it.next();
    	 		System.out.println(p.getId().toString()+":"+p.getName()+":"+p.getDesc());
    	 	}
    	 }catch(Exception ex){
    	 	ex.printStackTrace();
    	 }
    }
    
    public void testGroupCreate(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("Security");
    	
    	try{
    	  for(int i=1;i<101;i++){
    	  	Group grp = new Group();
    		grp.setGroupName("Group_Name_"+i);
    		grp.setGroupDesc("Group_Desc_"+i);
    	    upm.createGroup(grp);
    	  }
    	
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    public void testUserCreate(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("Security");
    	
    	try{
    	  for(int i=4;i<5001;i++){
    	  	User user = new User();
    	  	user.setLoginName("login_name_"+i);
    	  	user.setFirstName("User_first_name_"+i);
    	  	user.setLastName("User_last_name_"+i);
    	  	user.setDepartment("NCI_"+i);
    	  	user.setEmailId(user.getLastName()+"@mail.nih.nci.gov");
    	  	user.setOrganization("NIH");
    	  	
    	    upm.createUser(user);
    	    System.out.println("The returned id is"+user.getUserId());
    	  }
    	
    	
    	}catch(Exception ex){
    		ex.printStackTrace();
    	}
    }
    
    public void getUser(){
    	UserProvisioningManager upm = SecurityServiceProvider.getUserProvisioningManger("security");
    	 
    	 String loginName = "login_name_4";
    	 try{
    	 	User user = upm.getUser(loginName);
    	 	System.out.println(user.getFirstName()+":"+user.getEmailId());
    	 }catch(Exception ex){
    	 	ex.printStackTrace();
    	 }
    }
    
	public static void main(String[] args) {
		TestClient ts = new TestClient();
		//ts.testPrivilegeCreate();
		//ts.testPrivilegeDelete();
		//ts.testModifyCreate();
		//ts.testPrivilegeFind();
		//ts.testRoleCreate();
		//ts.testRoleDelete();
		//ts.testModifyRole();
		//ts.assignPrivilegeToRoles();
		//ts.getPrivileges();
		//ts.testGroupCreate();
		//ts.testUserCreate();
		//ts.getUser();
	}
}
