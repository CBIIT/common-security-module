/*L
   Copyright Ekagra Software Technologies Ltd.
   Copyright SAIC, SAIC-Frederick

   Distributed under the OSI-approved BSD 3-Clause License.
   See http://ncip.github.com/common-security-module/LICENSE.txt for details.
L*/

-- 
-- The following entries creates a super admin application incase you decide 
-- to use this database to run UPT also. In that case you need to provide
-- the project login id and name for the super admin.
-- However in incase you are using this database just to host the application's
-- authorization schema, these enteries are not used and hence they can be left as 
-- it is.
--

insert into csm_application(APPLICATION_ID, APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,UPDATE_DATE)
values (1, 'csmupt','UPT Super Admin Application',0,0,sysdate)
/

select CSM_APPLICATI_APPLICATION__SEQ.nextval from dual
/

INSERT INTO CSM_USER (USER_ID, LOGIN_NAME, MIGRATED_FLAG, FIRST_NAME, LAST_NAME, ORGANIZATION, DEPARTMENT, TITLE, PHONE_NUMBER, PASSWORD, EMAIL_ID, START_DATE, END_DATE, UPDATE_DATE, PREMGRT_LOGIN_NAME, PASSWORD_EXPIRED, PASSWORD_EXPIRY_DATE, FIRST_TIME_LOGIN, ACTIVE_FLAG) 
VALUES('1','SuperAdmin','0','aSxDyZ0AlthARx8irRHBhg==','YCwS7U4EuXsCiGXf1QMALA==','','','','','5kJqWYBdWCphljGP2pGUGg==','',NULL,NULL,sysdate,'','0','12-AUG-2013','0','1')
/
select CSM_USER_USER_ID_SEQ.nextval from dual
/

 
insert into csm_protection_element(PROTECTION_ELEMENT_ID, PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
values(1, 'csmupt','UPT Super Admin Application','csmupt',1,sysdate)
/

select CSM_PROTECTIO_PROTECTION_E_SEQ.nextval from dual
/

insert into csm_user_pe(USER_PROTECTION_ELEMENT_ID, PROTECTION_ELEMENT_ID,USER_ID)
values(1,1,1)
/

select CSM_USER_PE_USER_PROTECTIO_SEQ.nextval from dual
/

-- 
-- The following entry is for your application. 
-- Replace <<application_context>> with your application's context name.
--

INSERT INTO csm_application(APPLICATION_ID, APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,UPDATE_DATE)
VALUES (2, '<<application_context_name>>','Application Description',0,0,sysdate)
/

select CSM_APPLICATI_APPLICATION__SEQ.nextval from dual
/

insert into csm_protection_element(PROTECTION_ELEMENT_ID, PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
values(2, '<<application_context_name>>','<<application_context_name>> Admin Application','<<application_context_name>>',1,sysdate)
/

select CSM_PROTECTIO_PROTECTION_E_SEQ.nextval from dual
/

--
-- The following entries are Common Set of Privileges
--

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(1,'CREATE','This privilege grants permission to a user to create an entity. This entity can be an object, a database entry, or a resource such as a network connection', sysdate)
/

SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(2,'ACCESS','This privilege allows a user to access a particular resource.  Eg. network connection, database connection, socket, module of the application, or even the application itself', sysdate)
/

SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(3,'READ','This privilege permits the user to read data from a file, URL, socket, database, or an object. This can be used at an entity level signifying that the user is allowed to read a data row or object', sysdate)
/

SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(4,'WRITE','This privilege allows a user to write data to a file, URL, socket, database, or object. At an entity level it signified if user is allowed to write a data database row or object', sysdate)
/
SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(5,'UPDATE','This privilege grants permission At an entity level it signified if user is allowed to update and modify data for a particular entity.', sysdate)
/
SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(6,'DELETE','This privilege permits a user to delete a logical entity. This entity can be an object, a database entry, a resource such as a network connection, etc', sysdate)
/
SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO csm_privilege (privilege_id, privilege_name, privilege_description, update_date)
VALUES(7,'EXECUTE','This privilege allows a user to execute a particular resource. The resource can be a method, function, behavior of the application, URL, button etc', sysdate)
/
SELECT CSM_PRIVILEGE_PRIVILEGE_ID_SEQ.nextval FROM dual
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(1, 'UPT_UI_USERS_LINK', 'Protection Group representing User link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(2, 'UPT_UI_PROTECTION_ELEMENTS_LINK', 'Protection Group representing Protection Element link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(3, 'UPT_UI_PRIVILEGES_LINK', 'Protection Group representing Privilege link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(4, 'UPT_UI_GROUPS_LINK', 'Protection Group representing Group link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(5, 'UPT_UI_PROTECTION_GROUPS_LINK', 'Protection Group representing Protection Group link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(6, 'UPT_UI_ROLE_LINK', 'Protection Group representing Role link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES(7, 'UPT_UI_INSTANCE_LEVEL_LINK', 'Protection Group representing Instance Level link in UPT. Do not change the name.', 1, 0, sysdate)
/

INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('ALLOWED_ATTEMPTS','3')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('ALLOWED_LOGIN_TIME','600000')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('PASSWORD_EXPIRY_DAYS','60')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('PASSWORD_LOCKOUT_TIME','1800000')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('PASSWORD_MATCH_NUM','2')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('AES_ENCRYPTION_KEY','super secret')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('PASSWORD_PATTERN_MATCH','^.*(?=.{8,})(?=..*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$')
/
INSERT INTO CSM_CONFIGURATION_PROPS (PROPERTY_KEY, PROPERTY_VALUE) VALUES('PASSWORD_PATTERN_DESCRIPTION','At least one Upper case alphabet, at least one lower case alphabet, at least one number and minimum 8 characters length')
/
COMMIT
/
