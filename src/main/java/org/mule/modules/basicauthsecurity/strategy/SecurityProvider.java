package org.mule.modules.basicauthsecurity.strategy;

import org.mule.modules.basicauthsecurity.UnauthorizedException;

import java.util.List;

public interface SecurityProvider {

	void validate(String auth, List<String> acceptedRoles) throws UnauthorizedException;

}
