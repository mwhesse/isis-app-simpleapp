package domainapp.webapp.security.aad;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.isis.applib.annotation.OrderPrecedence;
import org.apache.isis.core.security.authentication.Authentication;
import org.apache.isis.core.security.authentication.AuthenticationContext;
import org.apache.isis.core.security.authentication.AuthenticationRequest;
import org.apache.isis.core.security.authentication.standard.Authenticator;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

@Service
@Named("isis.security.aad.AuthenticatedAuthenticator")
@Order(OrderPrecedence.EARLY)
public class AuthenticatedAuthenticator implements Authenticator {

    @Inject private AuthenticationContext authenticationTracker;
	
	@Override
	public boolean canAuthenticate(Class<? extends AuthenticationRequest> authenticationRequestClass) {
		return true;
	}

	@Override
	public Authentication authenticate(AuthenticationRequest request, String code) {
        return authenticationTracker.currentAuthentication().orElse(null);
	}

	@Override
	public void logout(Authentication session) {		
	}
	
}
