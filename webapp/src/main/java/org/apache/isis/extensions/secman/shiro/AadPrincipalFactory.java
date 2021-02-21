package org.apache.isis.extensions.secman.shiro;

import java.util.concurrent.Callable;
import java.util.function.Supplier;

import javax.inject.Inject;

import org.apache.isis.applib.services.inject.ServiceInjector;
import org.apache.isis.core.interaction.session.InteractionFactory;
import org.apache.isis.extensions.secman.api.user.AccountType;
import org.apache.isis.extensions.secman.api.user.ApplicationUser;
import org.apache.isis.extensions.secman.api.user.ApplicationUserRepository;
import org.apache.shiro.authc.CredentialsException;
import org.apache.shiro.authc.DisabledAccountException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.github.morulay.shiro.aad.PrincipalFactory;

import lombok.val;

@Component
public class AadPrincipalFactory implements PrincipalFactory {

	@Inject protected ServiceInjector serviceInjector;
	@Inject private InteractionFactory isisInteractionFactory;
    @Inject protected PlatformTransactionManager txMan;	
	
	@Override
	public Object createPrincipal(String username) {
		
        PrincipalForApplicationUser principal = lookupPrincipal_inApplicationUserRepository(username);
        
        if (principal == null) {
            throw credentialsException();
        }

        if (principal.isDisabled()) {
            throw disabledAccountException(principal.getUsername());
        }
        
        if(principal.getAccountType() != AccountType.DELEGATED) {
        	throw credentialsException();
        }
		
		return principal;
	}
	
    private PrincipalForApplicationUser lookupPrincipal_inApplicationUserRepository(final String username) {

        return execute(new Supplier<PrincipalForApplicationUser>() {
            @Override
            public PrincipalForApplicationUser get() {
                val applicationUser = applicationUserRepository.findByUsername(username).orElse(null);
                return PrincipalForApplicationUser.from(applicationUser);
            }
            @Inject private ApplicationUserRepository<? extends ApplicationUser> applicationUserRepository;
        });
    }
	
    <V> V execute(final Supplier<V> closure) {
        return isisInteractionFactory.callAnonymous(
                new Callable<V>() {
                    @Override
                    public V call() {
                        serviceInjector.injectServicesInto(closure);
                        return doExecute(closure);
                    }
                }
                );
    }

    <V> V doExecute(final Supplier<V> closure) {
        val txTemplate = new TransactionTemplate(txMan);
        return txTemplate.execute(status->closure.get());
    }
    
    private CredentialsException credentialsException() {
        return new CredentialsException("Unknown user");
    }
    private DisabledAccountException disabledAccountException(String username) {
        return new DisabledAccountException(String.format("username='%s'", username));
    }    

}