/*L
 *  Copyright Ekagra Software Technologies Ltd.
 *  Copyright SAIC, SAIC-Frederick
 *
 *  Distributed under the OSI-approved BSD 3-Clause License.
 *  See http://ncip.github.com/common-security-module/LICENSE.txt for details.
 */

package gov.nih.nci.security.authentication;

import org.apache.commons.configuration.event.ConfigurationErrorEvent;
import org.apache.commons.configuration.event.ConfigurationErrorListener;
import org.apache.commons.configuration.event.ConfigurationEvent;
import org.apache.commons.configuration.event.ConfigurationListener;

public class LockoutConfigurationListener implements ConfigurationListener,ConfigurationErrorListener {

	@Override
	public void configurationChanged(ConfigurationEvent event) {

        if (!event.isBeforeUpdate())
        {
            // only display events after the modification was done
            LockoutManager lockoutManager = LockoutManager.getInstance();
            if (event.getPropertyName() != null && event.getPropertyName().equalsIgnoreCase("PASSWORD_LOCKOUT_TIME"))
            {
            	if (event.getPropertyValue() != null)
            	{
            		String[] st = (String[]) event.getPropertyValue();
            		lockoutManager.setLockoutTime((Long.parseLong(st[0]))) ;
            	}
            }
            if (event.getPropertyName() != null && event.getPropertyName().equalsIgnoreCase("ALLOWED_LOGIN_TIME"))
            {
            	if (event.getPropertyValue() != null)
            	{
            		String[] st = (String[]) event.getPropertyValue();
            		lockoutManager.setAllowedLoginTime(Long.parseLong(st[0]));
            	}	
            }
            if (event.getPropertyName() != null && event.getPropertyName().equalsIgnoreCase("ALLOWED_ATTEMPTS"))
            {
            	if (event.getPropertyValue() != null)
            	{
            		String[] st = (String[]) event.getPropertyValue();
            		lockoutManager.setAllowedAttempts( Integer.parseInt(st[0]));
            	}
            } 
            LockoutManager lockoutManager2 = LockoutManager.getInstance();
        }
	}
	
    public void configurationError(ConfigurationErrorEvent event)
    {
        configurationChanged(event);
        event.getCause().printStackTrace();
    }

}
