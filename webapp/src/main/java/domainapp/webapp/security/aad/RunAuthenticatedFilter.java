package domainapp.webapp.security.aad;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.isis.applib.services.user.UserMemento;
import org.apache.isis.core.interaction.session.InteractionFactory;
import org.apache.isis.core.security.authentication.Authentication;
import org.apache.isis.core.security.authentication.standard.SimpleAuthentication;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;

public class RunAuthenticatedFilter implements Filter {

    @Autowired private InteractionFactory isisInteractionFactory;

	private static final String ID_TOKEN_PARAM = "id_token";
	static final SimpleCookie ID_TOKEN_COOKIE_TEMPLATE = new SimpleCookie(ID_TOKEN_PARAM);

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = WebUtils.toHttp(request);

		boolean hasIdToken = ID_TOKEN_COOKIE_TEMPLATE.readValue(httpRequest, null) != null;
		
		Subject subject = SecurityUtils.getSubject();
		
		if (hasIdToken && subject.isAuthenticated()) {
			
			String principalIdentity = subject.getPrincipal().toString();
			UserMemento user = UserMemento.ofNameAndRoleNames(principalIdentity, 
					Stream.of("org.apache.isis.viewer.wicket.roles.USER"));
			SimpleAuthentication authentication = SimpleAuthentication.validOf(user);
	        authentication.setType(Authentication.Type.EXTERNAL);
	        isisInteractionFactory.runAuthenticated(
	                authentication,
	                ()->{
	                	chain.doFilter(request, response);
	                });	        
		} else {
			
			chain.doFilter(request, response);
		}
	}

}
