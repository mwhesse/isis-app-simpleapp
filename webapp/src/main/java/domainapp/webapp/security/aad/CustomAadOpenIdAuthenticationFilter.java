package domainapp.webapp.security.aad;

import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import com.github.morulay.shiro.aad.AadOpenIdAuthenticationFilter;

public class CustomAadOpenIdAuthenticationFilter extends AadOpenIdAuthenticationFilter {

	public CustomAadOpenIdAuthenticationFilter(String authority, String tenant, String redirectUri, String clientId,
			String realmName, Set<String> noRedirectMimes) {
		super(authority, tenant, redirectUri, clientId, realmName, noRedirectMimes);
	}	
	
	/*
	 * Override the base method as we only want to be logged out in case of 
	 * an exception on completion.
	 * 
	 * Otherwise the login binds to the subject in case a (web) session is available.
	 */
	@Override
	public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception)
			throws Exception {
		
		if(exception != null) {
			Subject subject = SecurityUtils.getSubject();
			if(subject != null) {
				subject.logout();
			}
		}
	}	

}
