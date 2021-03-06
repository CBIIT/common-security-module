/*L
   Copyright Ekagra Software Technologies Ltd.
   Copyright SAIC, SAIC-Frederick

   Distributed under the OSI-approved BSD 3-Clause License.
   See http://ncip.github.com/common-security-module/LICENSE.txt for details.
L*/

CREATE OR REPLACE TRIGGER Log_APP_PRIVILEGE_Changes
  BEFORE INSERT OR DELETE OR UPDATE ON AS_APPLICATION_PRIVILEGE
  FOR EACH ROW
DECLARE
  V_ChangeType CHAR(1);
  oldTempRec  VARCHAR2(700);
  newTempRec  VARCHAR2(700);
  V_RecordId  NUMBER;
  V_TableName VARCHAR2(100);
  V_AttributeName VARCHAR2(80);


BEGIN
  V_TableName := 'AS_APPLICATION_PRIVILEGE';
  V_AttributeName := 'all_columns';

  /* User 'I' for an INSERT, 'D' for DELETE, and 'U' for UPDATE. */
  IF INSERTING THEN
    v_ChangeType := 'I';
	oldTempRec := 'not existing yet';
	V_RecordId := :new.APPLICATION_PRIVILEGE_ID;
	newTempRec := TO_CHAR(:new.UPDATE_DATE) || '|'  
	    	  || TO_CHAR(:new.APPLICATION_ID) || '|'
            	  || TO_CHAR(:new.PRIVILEGE_ID) || '|'
	    	  || TO_CHAR(:new.APPLICATION_PRIVILEGE_ID); 

  ELSIF UPDATING THEN
    v_ChangeType := 'U';
	V_RecordId := :old.APPLICATION_PRIVILEGE_ID;
	oldTempRec := TO_CHAR(:old.UPDATE_DATE) || '|'  
	    	  || TO_CHAR(:old.APPLICATION_ID) || '|'
            	  || TO_CHAR(:old.PRIVILEGE_ID) || '|'
	    	  || TO_CHAR(:old.APPLICATION_PRIVILEGE_ID); 

	newTempRec := TO_CHAR(:new.UPDATE_DATE) || '|'  
	    	  || TO_CHAR(:new.APPLICATION_ID) || '|'
            	  || TO_CHAR(:new.PRIVILEGE_ID) || '|'
	    	  || TO_CHAR(:new.APPLICATION_PRIVILEGE_ID); 


  ELSE
    v_ChangeType := 'D';
	V_RecordId := :old.APPLICATION_PRIVILEGE_ID;
	oldTempRec := TO_CHAR(:old.UPDATE_DATE) || '|'  
	    	  || TO_CHAR(:old.APPLICATION_ID) || '|'
            	  || TO_CHAR(:old.PRIVILEGE_ID) || '|'
	    	  || TO_CHAR(:old.APPLICATION_PRIVILEGE_ID); 

	newTempRec := 'deleted';

  END IF;


  /* Record all the changes made to AS_APPLICATION_PRIVILEGE in AS_LOG. Use
     SYSDATE to generate the timestamp, ad USER to return the
     userid of the current user*/
  INSERT INTO AS_LOG
  (
    TIMESTAMP, TABLE_NAME, RECORD_ID, ACTION_TYPE, ATTRIBUTE_NAME,
	OLD_VALUE, NEW_VALUE, LOG_ID, ACTION_USER_NAME
  )
  VALUES
  (
    to_number(to_char(sysdate,'yyyymmddhhmiss')), V_TableName,V_RecordId, v_ChangeType, V_AttributeName,
	oldTempRec, newTempRec, SEQ_LOGID.nextval, USER
  );
END Log_APP_PRIVILEGE_Changes;

