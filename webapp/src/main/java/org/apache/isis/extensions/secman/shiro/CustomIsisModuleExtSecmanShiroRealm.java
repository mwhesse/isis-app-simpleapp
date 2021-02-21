package org.apache.isis.extensions.secman.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.CredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;

import lombok.extern.log4j.Log4j2;

@Log4j2
public class CustomIsisModuleExtSecmanShiroRealm extends IsisModuleExtSecmanShiroRealm {
	
    @Override
	public boolean supports(AuthenticationToken token) {
    	/*
    	 * ask the delegate realm
    	 */
		return (getDelegateAuthenticationRealm() != null && getDelegateAuthenticationRealm().supports(token)) || super.supports(token);
	}

	@Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		AuthenticatingRealm delegateRealm = getDelegateAuthenticationRealm();
		/*
		 * let the delegate realm take precedence if the base class doesn't support this token
		 */
    	if(! super.supports(token) && delegateRealm != null && delegateRealm.supports(token)) {
	        AuthenticationInfo delegateAccount = null;
	        try {
	        	/*
	        	 *  - the realm calls the authenticate method of the authenticator
	        	 *  - the authenticator validates the token
	        	 *  - the authenticator calls the principal factory
	        	 *  - the principal factory constructs a PrincipalForApplicationUser
	        	 *    from the SecMan user entity (if found and conditions apply)
	        	 */
	            delegateAccount = delegateRealm.getAuthenticationInfo(token);
	        } catch (AuthenticationException ex) {
	            // fall through
	        	log.error(ex.getMessage(), ex);
	        }
	        if(delegateAccount == null) {
	            throw new CredentialsException();
	        }
	        /*
	         * The AuthenticationInfo received from AADRealm needs to be
	         * mapped to our AuthInfoForApplicationUser using the 
	         * PrincipalForApplicationUser created by the custom AAD 
	         * principal factory
	         */
	        if(delegateAccount instanceof SimpleAuthenticationInfo) {
	        	SimpleAuthenticationInfo simple = (SimpleAuthenticationInfo) delegateAccount;
	        	PrincipalForApplicationUser principal = (PrincipalForApplicationUser) simple.getPrincipals().getPrimaryPrincipal();		        	
	            return AuthInfoForApplicationUser.of(principal, getName(), simple.getCredentials());
	        }    			
		} /* else {
			log.warn("delegate realm not set or not supporting OpenIdToken: " + delegateRealm);
		} */
		//
    	return super.doGetAuthenticationInfo(token);
    }
}
