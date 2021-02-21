package domainapp.webapp.security.aad;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import com.github.morulay.shiro.aad.AadAuthenticator;
import com.github.morulay.shiro.aad.OpenIdToken;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class AadShiroRealm extends AuthorizingRealm {

	private final AadAuthenticator aadAuthenticator;
	
	@Override
	public boolean supports(AuthenticationToken token) {
		return token != null && OpenIdToken.class.isAssignableFrom(token.getClass());
	}

	@Override
	protected void onInit() {
		super.onInit();
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// not used
		return null;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		return aadAuthenticator.authenticate(token);
	}
}
