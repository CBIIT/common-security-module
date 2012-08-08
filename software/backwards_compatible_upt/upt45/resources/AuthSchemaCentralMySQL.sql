#This Schema is replica of latest version CSM 4.2

CREATE TABLE CSM_APPLICATION ( 
	APPLICATION_ID BIGINT AUTO_INCREMENT  NOT NULL,
	APPLICATION_NAME VARCHAR(255) NOT NULL,
	APPLICATION_DESCRIPTION VARCHAR(200) NOT NULL,
	DECLARATIVE_FLAG BOOL NOT NULL DEFAULT 0,
	ACTIVE_FLAG BOOL NOT NULL DEFAULT 0,
	UPDATE_DATE DATE DEFAULT '0000-00-00',
	DATABASE_URL VARCHAR(100),
	DATABASE_USER_NAME VARCHAR(100),
	DATABASE_PASSWORD VARCHAR(100),
	DATABASE_DIALECT VARCHAR(100),
	DATABASE_DRIVER VARCHAR(100),
	CSM_VERSION VARCHAR(20),
	PRIMARY KEY(APPLICATION_ID)
)Type=InnoDB
;

CREATE TABLE CSM_GROUP ( 
	GROUP_ID BIGINT AUTO_INCREMENT  NOT NULL,
	GROUP_NAME VARCHAR(255) NOT NULL,
	GROUP_DESC VARCHAR(200),
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	APPLICATION_ID BIGINT NOT NULL,
	PRIMARY KEY(GROUP_ID)
)Type=InnoDB
;

CREATE TABLE CSM_PRIVILEGE ( 
	PRIVILEGE_ID BIGINT AUTO_INCREMENT  NOT NULL,
	PRIVILEGE_NAME VARCHAR(100) NOT NULL,
	PRIVILEGE_DESCRIPTION VARCHAR(200),
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PRIMARY KEY(PRIVILEGE_ID)
)Type=InnoDB
;

CREATE TABLE CSM_FILTER_CLAUSE ( 
	FILTER_CLAUSE_ID BIGINT AUTO_INCREMENT  NOT NULL,
	CLASS_NAME VARCHAR(100) NOT NULL,
	FILTER_CHAIN VARCHAR(2000) NOT NULL,
	TARGET_CLASS_NAME VARCHAR (100) NOT NULL,
	TARGET_CLASS_ATTRIBUTE_NAME VARCHAR (100) NOT NULL,
	TARGET_CLASS_ATTRIBUTE_TYPE VARCHAR (100) NOT NULL,
	TARGET_CLASS_ALIAS VARCHAR (100),
	TARGET_CLASS_ATTRIBUTE_ALIAS VARCHAR (100),
	GENERATED_SQL_USER VARCHAR (4000) NOT NULL,
	GENERATED_SQL_GROUP VARCHAR (4000) NOT NULL,
	APPLICATION_ID BIGINT NOT NULL,
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PRIMARY KEY(FILTER_CLAUSE_ID)	
)Type=InnoDB 
;

CREATE TABLE CSM_MAPPING (
  MAPPING_ID bigint(20) NOT NULL auto_increment,
  APPLICATION_ID bigint(20) NOT NULL,
  OBJECT_NAME varchar(100) NOT NULL,
  ATTRIBUTE_NAME varchar(100) NOT NULL,
  OBJECT_PACKAGE_NAME varchar(100),
  TABLE_NAME varchar(100),
  TABLE_NAME_GROUP varchar(100),
  TABLE_NAME_USER varchar(100),
  VIEW_NAME_GROUP varchar(100),
  VIEW_NAME_USER varchar(100),
  ACTIVE_FLAG tinyint(1) NOT NULL default '0',
  MAINTAINED_FLAG tinyint(1) NOT NULL default '0',	
  UPDATE_DATE date default '0000-00-00',
  PRIMARY KEY(MAPPING_ID)
)Type=InnoDB
;

CREATE TABLE CSM_PROTECTION_ELEMENT ( 
	PROTECTION_ELEMENT_ID BIGINT AUTO_INCREMENT  NOT NULL,
	PROTECTION_ELEMENT_NAME VARCHAR(100) NOT NULL,
	PROTECTION_ELEMENT_DESCRIPTION VARCHAR(200),
	OBJECT_ID VARCHAR(100) NOT NULL,
	ATTRIBUTE VARCHAR(100) ,
	ATTRIBUTE_VALUE VARCHAR(100) ,
	PROTECTION_ELEMENT_TYPE VARCHAR(100),
	APPLICATION_ID BIGINT NOT NULL,
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PRIMARY KEY(PROTECTION_ELEMENT_ID)
)Type=InnoDB
;

CREATE TABLE CSM_PROTECTION_GROUP ( 
	PROTECTION_GROUP_ID BIGINT AUTO_INCREMENT  NOT NULL,
	PROTECTION_GROUP_NAME VARCHAR(100) NOT NULL,
	PROTECTION_GROUP_DESCRIPTION VARCHAR(200),
	APPLICATION_ID BIGINT NOT NULL,
	LARGE_ELEMENT_COUNT_FLAG BOOL NOT NULL,
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PARENT_PROTECTION_GROUP_ID BIGINT,
	PRIMARY KEY(PROTECTION_GROUP_ID)
)Type=InnoDB
;

CREATE TABLE CSM_PG_PE ( 
	PG_PE_ID BIGINT AUTO_INCREMENT  NOT NULL,
	PROTECTION_GROUP_ID BIGINT NOT NULL,
	PROTECTION_ELEMENT_ID BIGINT NOT NULL,
	UPDATE_DATE DATE DEFAULT '0000-00-00',
	PRIMARY KEY(PG_PE_ID)
)Type=InnoDB
;

CREATE TABLE CSM_ROLE ( 
	ROLE_ID BIGINT AUTO_INCREMENT  NOT NULL,
	ROLE_NAME VARCHAR(100) NOT NULL,
	ROLE_DESCRIPTION VARCHAR(200),
	APPLICATION_ID BIGINT NOT NULL,
	ACTIVE_FLAG BOOL NOT NULL,
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PRIMARY KEY(ROLE_ID)
)Type=InnoDB
;

CREATE TABLE CSM_ROLE_PRIVILEGE ( 
	ROLE_PRIVILEGE_ID BIGINT AUTO_INCREMENT  NOT NULL,
	ROLE_ID BIGINT NOT NULL,
	PRIVILEGE_ID BIGINT NOT NULL,
	PRIMARY KEY(ROLE_PRIVILEGE_ID)
)Type=InnoDB
;

CREATE TABLE `CSM_USER` (
  `USER_ID` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `LOGIN_NAME` VARCHAR(500) NOT NULL,
  `MIGRATED_FLAG` TINYINT(1) NOT NULL DEFAULT '0',
  `FIRST_NAME` VARCHAR(100) NOT NULL,
  `LAST_NAME` VARCHAR(100) NOT NULL,
  `ORGANIZATION` VARCHAR(100) DEFAULT NULL,
  `DEPARTMENT` VARCHAR(100) DEFAULT NULL,
  `TITLE` VARCHAR(100) DEFAULT NULL,
  `PHONE_NUMBER` VARCHAR(100) DEFAULT NULL,
  `PASSWORD` VARCHAR(100) DEFAULT NULL,
  `EMAIL_ID` VARCHAR(100) DEFAULT NULL,
  `START_DATE` DATE DEFAULT NULL,
  `END_DATE` DATE DEFAULT NULL,
  `UPDATE_DATE` DATE NOT NULL DEFAULT '0000-00-00',
  `PREMGRT_LOGIN_NAME` VARCHAR(100) DEFAULT NULL,
  `PASSWORD_EXPIRED` TINYINT (1),
  `PASSWORD_EXPIRY_DATE` DATE ,
  `FIRST_TIME_LOGIN` TINYINT (1),
  `ACTIVE_FLAG` TINYINT (1),
  PRIMARY KEY (`USER_ID`)
) ENGINE=INNODB;


CREATE TABLE CSM_USER_GROUP ( 
	USER_GROUP_ID BIGINT AUTO_INCREMENT  NOT NULL,
	USER_ID BIGINT NOT NULL,
	GROUP_ID BIGINT NOT NULL,
	PRIMARY KEY(USER_GROUP_ID)
)Type=InnoDB
;

CREATE TABLE CSM_USER_GROUP_ROLE_PG ( 
	USER_GROUP_ROLE_PG_ID BIGINT AUTO_INCREMENT  NOT NULL,
	USER_ID BIGINT,
	GROUP_ID BIGINT,
	ROLE_ID BIGINT NOT NULL,
	PROTECTION_GROUP_ID BIGINT NOT NULL,
	UPDATE_DATE DATE NOT NULL DEFAULT '0000-00-00',
	PRIMARY KEY(USER_GROUP_ROLE_PG_ID)
)Type=InnoDB
;

CREATE TABLE CSM_USER_PE ( 
	USER_PROTECTION_ELEMENT_ID BIGINT AUTO_INCREMENT  NOT NULL,
	PROTECTION_ELEMENT_ID BIGINT NOT NULL,
	USER_ID BIGINT NOT NULL,
	PRIMARY KEY(USER_PROTECTION_ELEMENT_ID)
)Type=InnoDB
;

CREATE TABLE CSM_PASSWORD_HISTORY (
	CSM_PASSWORD_HISTORY_ID BIGINT(20) NOT NULL AUTO_INCREMENT,
	LOGIN_NAME VARCHAR (500),
	PASSWORD VARCHAR (100),
	PRIMARY KEY(CSM_PASSWORD_HISTORY_ID)
)Type=InnoDB
;

CREATE TABLE CSM_CONFIGURATION_PROPERTIES (
	PROPERTY_KEY VARCHAR (100),
	PROPERTY_VALUE VARCHAR (500)
)Type=InnoDB
;

ALTER TABLE CSM_MAPPING ADD CONSTRAINT FK_PE_APPLICATION 
FOREIGN KEY FK_PE_APPLICATION (APPLICATION_ID) REFERENCES csm_application (APPLICATION_ID) ON DELETE CASCADE
;

ALTER TABLE CSM_MAPPING
ADD CONSTRAINT UQ_MP_OBJ_NAME_ATTRI_NAME_APP_ID UNIQUE (OBJECT_NAME,ATTRIBUTE_NAME,APPLICATION_ID)
;


ALTER TABLE CSM_APPLICATION
ADD CONSTRAINT UQ_APPLICATION_NAME UNIQUE (APPLICATION_NAME)
;

CREATE INDEX idx_CSM_PASSWORD_HISTORY_ID ON CSM_PASSWORD_HISTORY(CSM_PASSWORD_HISTORY_ID)
;

CREATE INDEX idx_APPLICATION_ID ON CSM_GROUP(APPLICATION_ID)
;

ALTER TABLE CSM_GROUP
ADD CONSTRAINT UQ_GROUP_GROUP_NAME UNIQUE (APPLICATION_ID, GROUP_NAME)
;
ALTER TABLE CSM_PRIVILEGE
ADD CONSTRAINT UQ_PRIVILEGE_NAME UNIQUE (PRIVILEGE_NAME)
;
CREATE INDEX idx_APPLICATION_ID ON CSM_PROTECTION_ELEMENT(APPLICATION_ID)
;
CREATE INDEX idx_OBJ_ATTR_APP ON CSM_PROTECTION_ELEMENT(OBJECT_ID, ATTRIBUTE, APPLICATION_ID) 
;
ALTER TABLE CSM_PROTECTION_ELEMENT
ADD CONSTRAINT UQ_PE_PE_NAME_ATTRIBUTE_VALUE_APP_ID UNIQUE (OBJECT_ID, ATTRIBUTE, ATTRIBUTE_VALUE, APPLICATION_ID)
;
CREATE INDEX idx_APPLICATION_ID ON CSM_PROTECTION_GROUP(APPLICATION_ID)
;
ALTER TABLE CSM_PROTECTION_GROUP
ADD CONSTRAINT UQ_PROTECTION_GROUP_PROTECTION_GROUP_NAME UNIQUE (APPLICATION_ID, PROTECTION_GROUP_NAME)
;
CREATE INDEX idx_PARENT_PROTECTION_GROUP_ID ON CSM_PROTECTION_GROUP(PARENT_PROTECTION_GROUP_ID)
;
CREATE INDEX idx_PROTECTION_ELEMENT_ID ON CSM_PG_PE(PROTECTION_ELEMENT_ID)
;
CREATE INDEX idx_PROTECTION_GROUP_ID ON CSM_PG_PE(PROTECTION_GROUP_ID)
;
ALTER TABLE CSM_PG_PE
ADD CONSTRAINT UQ_PROTECTION_GROUP_PROTECTION_ELEMENT_PROTECTION_GROUP_ID UNIQUE (PROTECTION_ELEMENT_ID, PROTECTION_GROUP_ID)
;
CREATE INDEX idx_APPLICATION_ID ON CSM_ROLE(APPLICATION_ID)
;
ALTER TABLE CSM_ROLE
ADD CONSTRAINT UQ_ROLE_ROLE_NAME UNIQUE (APPLICATION_ID, ROLE_NAME)
;
CREATE INDEX idx_PRIVILEGE_ID ON CSM_ROLE_PRIVILEGE(PRIVILEGE_ID)
;
ALTER TABLE CSM_ROLE_PRIVILEGE
ADD CONSTRAINT UQ_ROLE_PRIVILEGE_ROLE_ID UNIQUE (PRIVILEGE_ID, ROLE_ID)
;
CREATE INDEX idx_ROLE_ID ON CSM_ROLE_PRIVILEGE(ROLE_ID)
;

ALTER TABLE CSM_USER
ADD CONSTRAINT UQ_LOGIN_NAME UNIQUE (LOGIN_NAME)
;
CREATE INDEX idx_USER_ID ON CSM_USER_GROUP(USER_ID)
;
CREATE INDEX idx_GROUP_ID ON CSM_USER_GROUP(GROUP_ID)
;
CREATE INDEX idx_GROUP_ID ON CSM_USER_GROUP_ROLE_PG(GROUP_ID)
;
CREATE INDEX idx_ROLE_ID ON CSM_USER_GROUP_ROLE_PG(ROLE_ID)
;
CREATE INDEX idx_PROTECTION_GROUP_ID ON CSM_USER_GROUP_ROLE_PG(PROTECTION_GROUP_ID)
;
CREATE INDEX idx_USER_ID ON CSM_USER_GROUP_ROLE_PG(USER_ID)
;
CREATE INDEX idx_USER_ID ON CSM_USER_PE(USER_ID)
;
CREATE INDEX idx_PROTECTION_ELEMENT_ID ON CSM_USER_PE(PROTECTION_ELEMENT_ID)
;
ALTER TABLE CSM_USER_PE
ADD CONSTRAINT UQ_USER_PROTECTION_ELEMENT_PROTECTION_ELEMENT_ID UNIQUE (USER_ID, PROTECTION_ELEMENT_ID)
;


ALTER TABLE CSM_PASSWORD_HISTORY ADD CONSTRAINT FK_PWD_LOGIN_NAME 
FOREIGN KEY (LOGIN_NAME) REFERENCES CSM_USER (LOGIN_NAME)
ON DELETE CASCADE
;

ALTER TABLE CSM_GROUP ADD CONSTRAINT FK_APPLICATION_GROUP 
FOREIGN KEY (APPLICATION_ID) REFERENCES CSM_APPLICATION (APPLICATION_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_FILTER_CLAUSE ADD CONSTRAINT FK_APPLICATION_FILTER_CLAUSE 
FOREIGN KEY (APPLICATION_ID) REFERENCES CSM_APPLICATION (APPLICATION_ID)
ON DELETE CASCADE
;

#ALTER TABLE CSM_PROTECTION_ELEMENT ADD CONSTRAINT FK_PE_APPLICATION 
#FOREIGN KEY (APPLICATION_ID) REFERENCES CSM_APPLICATION (APPLICATION_ID)
#ON DELETE CASCADE
#;

ALTER TABLE CSM_PROTECTION_GROUP ADD CONSTRAINT FK_PG_APPLICATION 
FOREIGN KEY (APPLICATION_ID) REFERENCES CSM_APPLICATION (APPLICATION_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_PROTECTION_GROUP ADD CONSTRAINT FK_PROTECTION_GROUP 
FOREIGN KEY (PARENT_PROTECTION_GROUP_ID) REFERENCES CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID)
;

ALTER TABLE CSM_PG_PE ADD CONSTRAINT FK_PROTECTION_ELEMENT_PROTECTION_GROUP 
FOREIGN KEY (PROTECTION_ELEMENT_ID) REFERENCES CSM_PROTECTION_ELEMENT (PROTECTION_ELEMENT_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_PG_PE ADD CONSTRAINT FK_PROTECTION_GROUP_PROTECTION_ELEMENT 
FOREIGN KEY (PROTECTION_GROUP_ID) REFERENCES CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_ROLE ADD CONSTRAINT FK_APPLICATION_ROLE 
FOREIGN KEY (APPLICATION_ID) REFERENCES CSM_APPLICATION (APPLICATION_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_ROLE_PRIVILEGE ADD CONSTRAINT FK_PRIVILEGE_ROLE 
FOREIGN KEY (PRIVILEGE_ID) REFERENCES CSM_PRIVILEGE (PRIVILEGE_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_ROLE_PRIVILEGE ADD CONSTRAINT FK_ROLE
FOREIGN KEY (ROLE_ID) REFERENCES CSM_ROLE (ROLE_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP ADD CONSTRAINT FK_USER_GROUP 
FOREIGN KEY (USER_ID) REFERENCES CSM_USER (USER_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP ADD CONSTRAINT FK_UG_GROUP 
FOREIGN KEY (GROUP_ID) REFERENCES CSM_GROUP (GROUP_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP_ROLE_PG ADD CONSTRAINT FK_USER_GROUP_ROLE_PROTECTION_GROUP_GROUPS 
FOREIGN KEY (GROUP_ID) REFERENCES CSM_GROUP (GROUP_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP_ROLE_PG ADD CONSTRAINT FK_USER_GROUP_ROLE_PROTECTION_GROUP_ROLE 
FOREIGN KEY (ROLE_ID) REFERENCES CSM_ROLE (ROLE_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP_ROLE_PG ADD CONSTRAINT FK_USER_GROUP_ROLE_PROTECTION_GROUP_PROTECTION_GROUP 
FOREIGN KEY (PROTECTION_GROUP_ID) REFERENCES CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_GROUP_ROLE_PG ADD CONSTRAINT FK_USER_GROUP_ROLE_PROTECTION_GROUP_USER 
FOREIGN KEY (USER_ID) REFERENCES CSM_USER (USER_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_PE ADD CONSTRAINT FK_PE_USER 
FOREIGN KEY (USER_ID) REFERENCES CSM_USER (USER_ID)
ON DELETE CASCADE
;

ALTER TABLE CSM_USER_PE ADD CONSTRAINT FK_PROTECTION_ELEMENT_USER 
FOREIGN KEY (PROTECTION_ELEMENT_ID) REFERENCES CSM_PROTECTION_ELEMENT (PROTECTION_ELEMENT_ID)
ON DELETE CASCADE
;

#
# The following entries creates a super admin application incase you decide 
# to use this database to run UPT also. In that case you need to provide
# the project login id and name for the super admin.
# However in incase you are using this database just to host the application's
# authorization schema, these enteries are not used and hence they can be left as 
# it is.
#

INSERT INTO CSM_APPLICATION(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,CSM_VERSION,UPDATE_DATE)
VALUES ("@upt.central.context.name@","CSM UPT Super Admin Application",0,0,"",sysdate());

INSERT INTO `CSM_USER` (`USER_ID`, `LOGIN_NAME`, `MIGRATED_FLAG`, `FIRST_NAME`, `LAST_NAME`, `ORGANIZATION`, `DEPARTMENT`, `TITLE`, `PHONE_NUMBER`, `PASSWORD`, `EMAIL_ID`, `START_DATE`, `END_DATE`, `UPDATE_DATE`, `PREMGRT_LOGIN_NAME`, `PASSWORD_EXPIRED`, `PASSWORD_EXPIRY_DATE`, `FIRST_TIME_LOGIN`, `ACTIVE_FLAG`) 
VALUES('1','SuperAdmin','0','M+wyzKXPsnP1wroMZZzE5DgBjjg02ebtIvu5SOWEMIE=','Thpw3xS460e3wrR7wN/KpP7w79XCsWBfiLVlaSyVKsc=','VBWcSGeGvPBj4JaOjWzyiw==','P3FbU6Ag10CVvLoyVpPIog==','MEh5SB82uCoH9Trzgpy+7g==','ry0/5MmuvqzzOzpYcjk0Lg==','8bPrWwj63Gt4wigdAOMDBQ==','9AuOljOTQ3yb7G0Hd7KFuWRj4RPbRbZdicuSJeRMrwk=',NULL,NULL,'2012-08-07','','0','2012-09-17','0','1');

INSERT INTO `CSM_USER` (`USER_ID`, `LOGIN_NAME`, `MIGRATED_FLAG`, `FIRST_NAME`, `LAST_NAME`, `ORGANIZATION`, `DEPARTMENT`, `TITLE`, `PHONE_NUMBER`, `PASSWORD`, `EMAIL_ID`, `START_DATE`, `END_DATE`, `UPDATE_DATE`, `PREMGRT_LOGIN_NAME`, `PASSWORD_EXPIRED`, `PASSWORD_EXPIRY_DATE`, `FIRST_TIME_LOGIN`, `ACTIVE_FLAG`) 
VALUES('2','/O=caBIG/OU=caGrid/OU=Training/OU=Dorian/CN=parmarv','0','Vijay','Parmar',NULL,NULL,NULL,NULL,'zJPWCwDeSgG8j2uyHEABIQ==',NULL,NULL,NULL,'2012-05-24',NULL,'0','2012-09-17','0','1');

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("@upt.central.context.name@","CSM UPT Super Admin Application Protection Element","csmupt",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(1,1);

#
# The following entry is for your application.
# Replace <<application_context_name>> with your application name.
#


INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sampleHostApplicationName","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sampleHostApplicationName","Admin Application Protection Element","sampleHostApplicationName",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(2,1);

INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sample31","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sample31","Admin Application Protection Element","sample31",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(3,1);

INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sample32","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sample32","Admin Application Protection Element","sample32",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(4,1);

INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sample40","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sample40","Admin Application Protection Element","sample40",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(5,1);

INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sample41","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sample41","Admin Application Protection Element","sample41",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(6,1);

INSERT INTO csm_application(APPLICATION_NAME,APPLICATION_DESCRIPTION,DECLARATIVE_FLAG,ACTIVE_FLAG,
	DATABASE_URL,
	DATABASE_USER_NAME ,
	DATABASE_PASSWORD,
	DATABASE_DIALECT,
	DATABASE_DRIVER,
	CSM_VERSION,
	UPDATE_DATE)
VALUES ("sample424","Application Description",0,0,
	"jdbc:mysql://localhost:3306/csm_dev_bkwrdscmptbl_central",
	"root",
	"H/2qIBdj9TQ=",
	"org.hibernate.dialect.MySQLDialect",
	"org.gjt.mm.mysql.Driver","",
	sysdate());

INSERT INTO CSM_PROTECTION_ELEMENT(PROTECTION_ELEMENT_NAME,PROTECTION_ELEMENT_DESCRIPTION,OBJECT_ID,APPLICATION_ID,UPDATE_DATE)
VALUES("sample424","Admin Application Protection Element","sample424",1,sysdate());

INSERT INTO CSM_USER_PE(PROTECTION_ELEMENT_ID,USER_ID)
VALUES(7,1);
#
# The following entries are Common Set of Privileges
#

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("CREATE","This privilege grants permission to a user to create an entity. This entity can be an object, a database entry, or a resource such as a network connection", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("ACCESS","This privilege allows a user to access a particular resource.  Examples of resources include a network or database connection, socket, module of the application, or even the application itself", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("READ","This privilege permits the user to read data from a file, URL, database, an object, etc. This can be used at an entity level signifying that the user is allowed to read data about a particular entry", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("WRITE","This privilege allows a user to write data to a file, URL, database, an object, etc. This can be used at an entity level signifying that the user is allowed to write data about a particular entity", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("UPDATE","This privilege grants permission at an entity level and signifies that the user is allowed to update data for a particular entity. Entities may include an object, object attribute, database row etc", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("DELETE","This privilege permits a user to delete a logical entity. This entity can be an object, a database entry, a resource such as a network connection, etc", sysdate());

INSERT INTO csm_privilege (privilege_name, privilege_description, update_date)
VALUES("EXECUTE","This privilege allows a user to execute a particular resource. The resource can be a method, function, behavior of the application, URL, button etc", sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(1, 'UPT_UI_USERS_LINK', 'Protection Group representing User link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(2, 'UPT_UI_PROTECTION_ELEMENTS_LINK', 'Protection Group representing Protection Element link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(3, 'UPT_UI_PRIVILEGES_LINK', 'Protection Group representing Privilege link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(4, 'UPT_UI_GROUPS_LINK', 'Protection Group representing Group link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(5, 'UPT_UI_PROTECTION_GROUPS_LINK', 'Protection Group representing Protection Group link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(6, 'UPT_UI_ROLE_LINK', 'Protection Group representing Role link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT CSM_PROTECTION_GROUP (PROTECTION_GROUP_ID, PROTECTION_GROUP_NAME, PROTECTION_GROUP_DESCRIPTION, APPLICATION_ID, LARGE_ELEMENT_COUNT_FLAG, UPDATE_DATE)
VALUES
(7, 'UPT_UI_INSTANCE_LEVEL_LINK', 'Protection Group representing Instance Level link in UPT. Do not change the name.', 1, 0, sysdate());

INSERT INTO `CSM_CONFIGURATION_PROPERTIES` (`PROPERTY_KEY`, `PROPERTY_VALUE`) VALUES('ALLOWED_ATTEMPTS','3');
INSERT INTO `CSM_CONFIGURATION_PROPERTIES` (`PROPERTY_KEY`, `PROPERTY_VALUE`) VALUES('ALLOWED_LOGIN_TIME','600000');
INSERT INTO `CSM_CONFIGURATION_PROPERTIES` (`PROPERTY_KEY`, `PROPERTY_VALUE`) VALUES('PASSWORD_EXPIRY_DAYS','60');
INSERT INTO `CSM_CONFIGURATION_PROPERTIES` (`PROPERTY_KEY`, `PROPERTY_VALUE`) VALUES('PASSWORD_LOCKOUT_TIME','1800000');
INSERT INTO `CSM_CONFIGURATION_PROPERTIES` (`PROPERTY_KEY`, `PROPERTY_VALUE`) VALUES('PASSWORD_MATCH_NUM','2');
