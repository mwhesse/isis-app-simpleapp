package domainapp.webapp.security.aad;
import java.net.URI;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AadSessionController {

	@RequiresRoles("user")
	@RequestMapping("/aadLogin")
	public ResponseEntity<Void> login() {
		return ResponseEntity.status(HttpStatus.FOUND)
		        .location(URI.create("/wicket/"))
		        .build();
	}
	
	@RequestMapping("/aadLogout")
	public ResponseEntity<Boolean> logout() {
		return ResponseEntity.status(HttpStatus.FOUND)
		        .location(URI.create("/wicket/"))
		        .build();
	}	
}