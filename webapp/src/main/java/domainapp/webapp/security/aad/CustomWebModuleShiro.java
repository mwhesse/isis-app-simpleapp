package domainapp.webapp.security.aad;

import java.util.Collection;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;

import org.apache.isis.applib.annotation.OrderPrecedence;
import org.apache.isis.applib.services.inject.ServiceInjector;
import org.apache.isis.commons.collections.Can;
import org.apache.isis.commons.internal._Constants;
import org.apache.isis.commons.internal.base._Strings;
import org.apache.isis.extensions.secman.shiro.CustomIsisModuleExtSecmanShiroRealm;
import org.apache.isis.extensions.secman.shiro.IsisModuleExtSecmanShiroRealm;
import org.apache.isis.security.shiro.webmodule.WebModuleShiro;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;
import org.springframework.util.ReflectionUtils;

import com.github.morulay.shiro.aad.AadLogoutFilter;
import com.github.morulay.shiro.aad.spring.boot.autoconfigure.ShiroAadProperties;

import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.val;

@Service
@Named("isisSecurityShiro.WebModuleShiro")
@Order(OrderPrecedence.FIRST + 200)
@Qualifier("Shiro")
public class CustomWebModuleShiro extends WebModuleShiro {

    private static final String SHIRO_FILTER_NAME = "ShiroFilter";
	
	@Inject
	private ShiroAadProperties aadProperties;
	
    private final ServiceInjector _serviceInjector;	
    
    @Inject
    public CustomWebModuleShiro(final ServiceInjector serviceInjector) {
        super(serviceInjector);
        this._serviceInjector = serviceInjector;
    }
    
    /**
     * Adds support for dependency injection into security realms
     * @since 2.0
     */
    @NoArgsConstructor // don't remove, this is class is managed by Isis
    public static class MyEnvironmentLoaderListenerForIsis extends EnvironmentLoaderListener {

        @Inject 
        private ServiceInjector serviceInjector;
        
		@Inject
		private AadShiroRealm aadRealm;

        // testing support
        public MyEnvironmentLoaderListenerForIsis(ServiceInjector serviceInjector) {
            this.serviceInjector = serviceInjector;
        }

        @Override
        public void contextInitialized(ServletContextEvent sce) {
            super.contextInitialized(sce);
        }

        @Override 
        protected WebEnvironment createEnvironment(ServletContext servletContext) {
            val shiroEnvironment = super.createEnvironment(servletContext);
            val securityManager = shiroEnvironment.getSecurityManager();

            injectServicesIntoRealms(securityManager);
            
            setDelegateSecmanRealm((RealmSecurityManager) securityManager);
            
            return shiroEnvironment;
        }
        
        private void setDelegateSecmanRealm(RealmSecurityManager securityManager) {
            final Collection<Realm> realms = securityManager.getRealms();
            for (Realm realm : realms) {
                if(realm instanceof CustomIsisModuleExtSecmanShiroRealm) {
                	CustomIsisModuleExtSecmanShiroRealm imsr = (CustomIsisModuleExtSecmanShiroRealm) realm;
                    imsr.setDelegateAuthenticationRealm(aadRealm);
                    break;
                }
            }
		}

		@SuppressWarnings("unchecked")
        @SneakyThrows
        public void injectServicesIntoRealms(
                org.apache.shiro.mgt.SecurityManager securityManager) {

            // reflective access to SecurityManager.getRealms()
            val realms = (Collection<Realm>) ReflectionUtils
                    .findMethod(securityManager.getClass(), "getRealms")
                    .invoke(securityManager, _Constants.emptyObjects);

            realms.stream().forEach(serviceInjector::injectServicesInto);
        }
    }    
    
    @Override
    public Can<ServletContextListener> init(ServletContext ctx) throws ServletException {

        registerFilter(ctx, SHIRO_FILTER_NAME, ShiroFilter.class)
            .ifPresent(filterReg -> {
                filterReg.addMappingForUrlPatterns(
                        null,
                        false, // filter is forced first
                        "/*");
            });

        registerFilter(ctx, "RunAuthenticatedFilter", RunAuthenticatedFilter.class)
        .ifPresent(filterReg -> {
            filterReg.addMappingForUrlPatterns(
                    null,
                    true, // filter is not forced first
                    "/*");
        });        
        
        addFilter(ctx, "AadOpenIdAuthenticationFilter_login", 
        		newAadOpenIdAuthenticationFilter(aadProperties, aadProperties.getRedirectUri(), "/aadLogin"))
        .ifPresent(filterReg -> {
            filterReg.addMappingForUrlPatterns(
                    null,
                    false, // filter is forced first
                    "/aadLogin");
        });
        
        addFilter(ctx, "AadLogoutFilter", newAadLogoutFilter(aadProperties))
        .ifPresent(filterReg -> {
            filterReg.addMappingForUrlPatterns(
                    null,
                    true, // filter is not forced first
                    "/aadLogout");
        });
        
        val customShiroEnvironmentClassName = System.getProperty("shiroEnvironmentClass");
        if(_Strings.isNotEmpty(customShiroEnvironmentClassName)) {
            ctx.setInitParameter("shiroEnvironmentClass", customShiroEnvironmentClassName);
        }

        val listener = createListener(MyEnvironmentLoaderListenerForIsis.class);
        return Can.ofSingleton(listener);

    }
    
    private static Filter newAadLogoutFilter(ShiroAadProperties aadProperties) {
    	return new AadLogoutFilter(
				aadProperties.getAuthority(), 
				aadProperties.getTenant(), 
				aadProperties.getPostLogoutUri());
	}

	private static Filter newAadOpenIdAuthenticationFilter(ShiroAadProperties aadProperties, String redirectUri, String path) {
		CustomAadOpenIdAuthenticationFilter filter = new CustomAadOpenIdAuthenticationFilter(
				aadProperties.getAuthority(), 
				aadProperties.getTenant(), 
				redirectUri,
				aadProperties.getClientId(), 
				aadProperties.getRealmName(), 
				aadProperties.getNoRedirectMimes());
		filter.processPathConfig(path, null);
		return filter;
	}

	protected Optional<FilterRegistration.Dynamic> addFilter(
            final ServletContext ctx,
            final String filterName,
            final Filter filter) throws ServletException {
        final FilterRegistration.Dynamic filterReg = ctx.addFilter(filterName, filter);
        if(filterReg != null) {
            _serviceInjector.injectServicesInto(filter);
        }
        return Optional.ofNullable(filterReg);
    }    
    
}
