/**
 * (c) 2003-2015 MuleSoft, Inc. The software in this package is published under the terms of the CPAL v1.0 license,
 * a copy of which has been included with this distribution in the LICENSE.md file.
 */

package org.mule.modules.basicauthsecurity.strategy;

import org.mule.api.annotations.Configurable;
import org.mule.api.annotations.components.Configuration;
import org.mule.api.annotations.param.Default;
import org.mule.modules.basicauthsecurity.UnauthorizedException;

import java.util.List;
import java.util.Map;

/**
 * Configuration type Strategy
 *
 * @author MuleSoft, Inc.
 */
@Configuration(configElementName = "config-type", friendlyName = "Memory Security Provider Strategy")
public class MemorySecurityProviderStrategy implements SecurityProvider {
	
	@Configurable
	@Default("false")
	public Boolean usersAsMap;

	public Boolean getUsersAsMap() {
		return usersAsMap;
	}

	public void setUsersAsMap(Boolean usersAsMap) {
		this.usersAsMap = usersAsMap;
	}

	@Configurable
	List<String> users;

	public List<String> getUsers() {
		return users;
	}

	public void setUsers(List<String> users) {
		this.users = users;
	}
	
	@Configurable
	Map<String, String> usersMap;
	

	public Map<String, String> getUsersMap() {
		return usersMap;
	}

	public void setUsersMap(Map<String, String> usersMap) {
		this.usersMap = usersMap;
	}

	public void validate(String auth, List<String> acceptedRoles) throws UnauthorizedException {
		if (usersAsMap) {
			String password = usersMap.get(getUser(auth));
			if(password == null || !password.equals(getPass(auth))){
				throw new UnauthorizedException(auth.split(":")[0]);
			}
		} else {
			for (String userInMemory : users) {
				if (!(getUser(auth).equals(getUser(userInMemory)) && getPass(
						auth).equals(getPass(userInMemory)))) {
					throw new UnauthorizedException(auth.split(":")[0]);
				}
			}
		}
	}
	
	private String getUser(String auth){
		return auth.split(":")[0];
	}
	
	private String getPass(String auth){
		return auth.split(":")[1];
	}

}