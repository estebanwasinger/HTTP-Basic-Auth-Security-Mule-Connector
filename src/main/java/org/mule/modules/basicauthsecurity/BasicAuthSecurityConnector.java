/**
 * (c) 2003-2015 MuleSoft, Inc. The software in this package is published under the terms of the CPAL v1.0 license,
 * a copy of which has been included with this distribution in the LICENSE.md file.
 */

package org.mule.modules.basicauthsecurity;

import org.apache.log4j.Logger;
import org.mule.api.MuleEvent;
import org.mule.api.MuleMessage;
import org.mule.api.annotations.Category;
import org.mule.api.annotations.Config;
import org.mule.api.annotations.Connector;
import org.mule.api.annotations.Processor;
import org.mule.api.callback.SourceCallback;
import org.mule.api.transport.PropertyScope;
import org.mule.modules.basicauthsecurity.strategy.SecurityProvider;
import org.mule.util.Base64;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Anypoint Connector
 *
 * @author MuleSoft, Inc.
 */
@Category(name = "org.mule.tooling.category.security", description = "Security")
@Connector(name = "basic-auth-security", friendlyName = "HTTP Basic Auth Security")
public class BasicAuthSecurityConnector {
	
	private static final Logger logger = Logger.getLogger(BasicAuthSecurityConnector.class);

	@Config
	SecurityProvider connectionStrategy;
	
	@Processor(intercepting = true)
	public Object secure(SourceCallback callback, MuleEvent me, MuleMessage mm, List<String> acceptedRoles) throws Exception  {
		Map<String, Object> mapa = new HashMap<String, Object>();
		String authorization = null;
		try {
			String auth = me.getMessage().getInboundProperty("authorization");
			
			authorization = new String(Base64.decode(auth.substring(6)));
			getConnectionStrategy().validate(authorization,acceptedRoles);
			
			logger.info(authorization);
			for(String role : acceptedRoles){
				logger.info(role);
			}
		} catch (Exception e) {
			mapa.put("WWW-Authenticate", "Basic realm=\"Unathorized\"");
			mapa.put("Content-Length", 0);
			mapa.put("http.status", 401);
			me.getMessage().addProperties(mapa, PropertyScope.OUTBOUND);
			return me.getMessage().getPayload();
		}
		mapa.put("auth", authorization);
		me.getMessage().addProperties(mapa, PropertyScope.OUTBOUND);
		callback.process(me.getMessage().getPayload());
		return me.getMessage().getPayload();
	}

	public SecurityProvider getConnectionStrategy() {
		return connectionStrategy;
	}

	public void setConnectionStrategy(
			SecurityProvider connectionStrategy) {
		this.connectionStrategy = connectionStrategy;
	}

}