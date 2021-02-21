package domainapp.webapp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;

import com.github.morulay.shiro.aad.AadAuthenticator;
import com.github.morulay.shiro.aad.PrincipalFactory;
import com.github.morulay.shiro.aad.spring.boot.autoconfigure.ShiroAadProperties;

import org.apache.isis.core.config.presets.IsisPresets;
import org.apache.isis.core.runtimeservices.IsisModuleCoreRuntimeServices;
import org.apache.isis.extensions.flyway.impl.IsisModuleExtFlywayImpl;
import org.apache.isis.extensions.secman.api.SecmanConfiguration;
import org.apache.isis.extensions.secman.api.permission.PermissionsEvaluationService;
import org.apache.isis.extensions.secman.api.permission.PermissionsEvaluationServiceAllowBeatsVeto;
import org.apache.isis.extensions.secman.encryption.jbcrypt.IsisModuleExtSecmanEncryptionJbcrypt;
import org.apache.isis.extensions.secman.jdo.IsisModuleExtSecmanPersistenceJdo;
import org.apache.isis.extensions.secman.model.IsisModuleExtSecmanModel;
import org.apache.isis.extensions.secman.shiro.AadPrincipalFactory;
import org.apache.isis.extensions.secman.shiro.AuthenticationStrategyForIsisModuleSecurityRealm;
import org.apache.isis.extensions.secman.shiro.IsisModuleExtSecmanRealmShiro;
import org.apache.isis.persistence.jdo.datanucleus.IsisModuleJdoDatanucleus;
import org.apache.isis.security.shiro.IsisModuleSecurityShiro;
import org.apache.isis.security.shiro.authentication.AuthenticatorShiro;
import org.apache.isis.security.shiro.authorization.AuthorizorShiro;
import org.apache.isis.testing.fixtures.applib.IsisModuleTestingFixturesApplib;
import org.apache.isis.testing.h2console.ui.IsisModuleTestingH2ConsoleUi;
import org.apache.isis.viewer.restfulobjects.jaxrsresteasy4.IsisModuleViewerRestfulObjectsJaxrsResteasy4;
import org.apache.isis.viewer.wicket.viewer.IsisModuleViewerWicketViewer;
import org.apache.shiro.authc.pam.AuthenticationStrategy;

import domainapp.webapp.application.ApplicationModule;
import domainapp.webapp.application.fixture.scenarios.DomainAppDemo;
import domainapp.webapp.custom.CustomModule;
import domainapp.webapp.security.aad.AadShiroRealm;
import domainapp.webapp.security.aad.AuthenticatedAuthenticator;
import domainapp.webapp.security.aad.CustomWebModuleShiro;

@Configuration
@Import({
        IsisModuleCoreRuntimeServices.class,
        
        // IsisModuleSecurityShiro.class,
        //
        AuthenticatedAuthenticator.class,
        AuthenticatorShiro.class,
        AuthorizorShiro.class,
        CustomWebModuleShiro.class,
        AadPrincipalFactory.class,     
        
        IsisModuleJdoDatanucleus.class,

        IsisModuleViewerRestfulObjectsJaxrsResteasy4.class,
        IsisModuleViewerWicketViewer.class,

        IsisModuleTestingFixturesApplib.class,
        IsisModuleTestingH2ConsoleUi.class,

        IsisModuleExtFlywayImpl.class,

        ApplicationModule.class,
        CustomModule.class,
        
        // Security Manager Extension (secman)
        IsisModuleExtSecmanModel.class,
        IsisModuleExtSecmanRealmShiro.class,
        IsisModuleExtSecmanPersistenceJdo.class,
        IsisModuleExtSecmanEncryptionJbcrypt.class,
        //
        ShiroAadProperties.class,        

        // discoverable fixtures
        DomainAppDemo.class
})
@PropertySources({
        @PropertySource(IsisPresets.DebugDiscovery),
})
public class AppManifest {

	@Bean
    public SecmanConfiguration  securityModuleConfigBean() {
        return SecmanConfiguration.builder()
                .adminUserName("sven")
                .adminAdditionalNamespacePermission("simple") 
                .adminAdditionalNamespacePermission("domainapp")
                .adminAdditionalNamespacePermission("org.apache.isis")
                .adminAdditionalNamespacePermission("isis")
                .build();
    }
    
    @Bean
    public AadAuthenticator aadAuthenticator(ShiroAadProperties aadProperties, PrincipalFactory principalFactory) {
    	AadAuthenticator aadAuthenticator = new AadAuthenticator(
				aadProperties.getAuthority(), 
				aadProperties.getTenantId(), 
				aadProperties.getClientId(), 
				aadProperties.getRealmName(),
				principalFactory);
    	return aadAuthenticator; 
    }
    
    @Bean
    public AadShiroRealm aadRealm(AadAuthenticator aadAuthenticator) {
    	return new AadShiroRealm(aadAuthenticator);
    }
    
    @Bean
    public PermissionsEvaluationService permissionsEvaluationService() {
        return new PermissionsEvaluationServiceAllowBeatsVeto();
    }
    
    @Bean
    public AuthenticationStrategy authenticationStrategy() {
    	return new AuthenticationStrategyForIsisModuleSecurityRealm();
    }
	
}
