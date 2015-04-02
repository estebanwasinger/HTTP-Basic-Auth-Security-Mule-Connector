/**
 * (c) 2003-2015 MuleSoft, Inc. The software in this package is published under the terms of the CPAL v1.0 license,
 * a copy of which has been included with this distribution in the LICENSE.md file.
 */

package org.mule.modules.basicauthsecurity.strategy;

import org.mule.api.ConnectionException;
import org.mule.api.ConnectionExceptionCode;
import org.mule.api.annotations.*;
import org.mule.api.annotations.components.ConnectionManagement;
import org.mule.api.annotations.display.FriendlyName;
import org.mule.api.annotations.display.Password;
import org.mule.api.annotations.display.Placement;
import org.mule.api.annotations.param.ConnectionKey;
import org.mule.api.annotations.param.Optional;
import org.mule.modules.basicauthsecurity.UnauthorizedException;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration type Strategy
 *
 * @author MuleSoft, Inc.
 */
@ConnectionManagement(configElementName = "jdbc-config-type", friendlyName = "JDBC Security Provider Strategy")
public class JDBCSecurityProvider implements SecurityProvider {

    DriverManagerDataSource managerDataSource;
    JdbcUserDetailsManager jdbcUserDetailsManager;
    DaoAuthenticationProvider daoAuthenticationProvider;
    ProviderManager providerManager;

    @Placement(group = "Query Settings")
    @Optional
    @Configurable
    String usersByUsernameQuery;

    @Placement(group = "Query Settings")
    @Configurable
    @Optional
    String authoritiesByUsernameQuery;

    @Override
    public void validate(String auth, List<String> acceptedRoles) throws UnauthorizedException {
        List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
        for(String role : acceptedRoles){
            list.add(new SimpleGrantedAuthority(role));
        }
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(getUser(auth), getPass(auth), list);
        Authentication authResult = providerManager.authenticate(authRequest);

        Boolean containsKey = false;
        for(GrantedAuthority grantedAuthority : authResult.getAuthorities()){
            if(authRequest.getAuthorities().contains(grantedAuthority)){
                containsKey = true;
            }
        }

        if(!containsKey){
            throw new UnauthorizedException("result");
        }
        if (!authResult.isAuthenticated()) {
            throw new UnauthorizedException("result");
        }
    }

    @Connect
    @TestConnectivity(label = "Test DB Configuration")
    public void connect(@ConnectionKey String username, @Password String password, @FriendlyName("DataBase URL") String url, String driverClassName)
            throws ConnectionException {
        managerDataSource = new DriverManagerDataSource();
        managerDataSource.setUsername(username);
        managerDataSource.setPassword(password);
        managerDataSource.setUrl(url);
        managerDataSource.setDriverClassName(driverClassName);

        try {
            if (!managerDataSource.getConnection().isValid(1000)) {
                throw new ConnectionException(ConnectionExceptionCode.INCORRECT_CREDENTIALS, "Incorrect credentials", "Incorrect credentials");
            }
        } catch (SQLException e) {
            throw new ConnectionException(ConnectionExceptionCode.INCORRECT_CREDENTIALS, "Incorrect credentials", "Incorrect credentials");
        }

        jdbcUserDetailsManager = new JdbcUserDetailsManager();
        setCustomQueries();

        jdbcUserDetailsManager.setDataSource(managerDataSource);

        daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(jdbcUserDetailsManager);

        List<AuthenticationProvider> list = new ArrayList<AuthenticationProvider>();
        list.add(daoAuthenticationProvider);
        providerManager = new ProviderManager(list);
    }

    private void setCustomQueries() {
        if (authoritiesByUsernameQuery != null) {
            jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(authoritiesByUsernameQuery);
        }
        if (usersByUsernameQuery != null) {
            jdbcUserDetailsManager.setUsersByUsernameQuery(usersByUsernameQuery);
        }
    }

    /**
     * Disconnect
     */
    @Disconnect
    public void disconnect() {
        /*
         * CODE FOR CLOSING A CONNECTION GOES IN HERE
         */
    }

    /**
     * Are we connected
     */
    @ValidateConnection
    public boolean isConnected() {
        if (managerDataSource == null) {
            return false;
        }
        try {
            Boolean result = managerDataSource.getConnection().isValid(1000);
            return result;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Are we connected
     */
    @ConnectionIdentifier
    public String connectionId() {
        return "001";
    }


    public String getUsersByUsernameQuery() {
        return usersByUsernameQuery;
    }

    public void setUsersByUsernameQuery(String usersByUsernameQuery) {
        this.usersByUsernameQuery = usersByUsernameQuery;
    }

    public String getAuthoritiesByUsernameQuery() {
        return authoritiesByUsernameQuery;
    }

    public void setAuthoritiesByUsernameQuery(String authoritiesByUsernameQuery) {
        this.authoritiesByUsernameQuery = authoritiesByUsernameQuery;
    }

    private String getUser(String auth) {
        return auth.split(":")[0];
    }

    private String getPass(String auth) {
        return auth.split(":")[1];
    }

}