package com.grocery;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.grocery.model.LoginForm;
import com.grocery.security.JwtAuthEntryPoint;
import com.grocery.security.JwtAuthTokenFilter;
import com.grocery.security.JwtProvider;
import com.grocery.security.JwtResponse;
import com.grocery.service.UserDetailsServiceImpl;
//Enables Spring Boot�s auto-configuration mechanism, package scan, and registering extra beans in the
//context or import additional configuration classes
@SpringBootApplication
@ComponentScan
@EnableOAuth2Sso // Enables OAuth2 Single Sign On, will automatically use application.yml
// properties for security
@RestController // Enabling REST functionality. With this, we can now expose our own endpoints
@EnableFeignClients("com.grocery")
@EnableDiscoveryClient
public class GroceryStoreApplication extends WebSecurityConfigurerAdapter {



	@Autowired
	JwtProvider jwtProvider;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Autowired
	private JwtAuthEntryPoint unauthorizedHandler;

	@Bean
	public JwtAuthTokenFilter authenticationJwtTokenFilter() {
		return new JwtAuthTokenFilter();
	}

	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder
		.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder());
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.cors().and().csrf().disable().
//		authorizeRequests()
//		.antMatchers("/login**", "/user", "/userInfo")
//		.permitAll();
//		//	                .anyRequest().authenticated()
//		//	                .and()
//		//	                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
//		//	                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//		//	        
//		//	        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
//	}

	public static void main(String[] args) {
		SpringApplication.run(GroceryStoreApplication.class, args);
	}


		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// Configuring Spring security access. For /login, /user, and /userinfo, we need
			// authentication.
			// Logout is enabled.
			// Adding csrf token support to this configurer. "/login**", "/user", "/userInfo"
			http.authorizeRequests().antMatchers("/login**", "/user", "/userInfo","/signin").authenticated().and().logout()
					.logoutSuccessUrl("/").permitAll();
//					.and().csrf()
//					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
		}

//	@PostMapping("/signin")
//	public ResponseEntity<?> authenticateUser(LoginForm loginRequest) {
//		System.out.println("GroceryStoreController.authenticateUser()");
//		Authentication authentication = authenticationManager.authenticate(
//				new UsernamePasswordAuthenticationToken(
//						loginRequest.getUsername(),
//						loginRequest.getPassword()
//						)
//				);
//
//		SecurityContextHolder.getContext().setAuthentication(authentication);
//
//		String jwt = jwtProvider.generateJwtToken(authentication);
//		System.out.println("generated JWT token --> "+jwt);
//		return ResponseEntity.ok(new JwtResponse(jwt));
//	}

	//	@PostMapping("/signin")
		public ResponseEntity<?> authenticateUser(LoginForm loginRequest) {
			System.out.println("GroceryStoreController.authenticateUser()");
			
//			authenticationManager.inMemoryAuthentication().withUser("javainuse-user").password("javainuse-pass").roles("USER");
			
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(
							loginRequest.getUsername(),
							loginRequest.getPassword()
							)
					);
	
			SecurityContextHolder.getContext().setAuthentication(authentication);
	
			String jwt = jwtProvider.generateJwtToken(authentication);
			System.out.println("generated JWT token --> "+jwt);
			return ResponseEntity.ok(new JwtResponse(jwt));
		}


	@RequestMapping("/user")
	public Principal user(Principal principal) {
		System.out.println("GroceryStoreController.user()");
		// Principal holds the logged in user information.
		// Spring automatically populates this principal object after login.
		final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
		final Authentication authentication = oAuth2Authentication.getUserAuthentication();

		/*
		 * String userName = authentication.getName(); LoginForm loginForm = new
		 * LoginForm(); loginForm.setUsername("pournima.shinde@in.ibm.com");
		 * loginForm.setPassword("Horizon@2021");
		 * System.out.println("authentication.getName()--> "+userName);
		 * authenticateUser(loginForm);
		 */
		return principal;
	}
	@RequestMapping("/userInfo")
	public String userInfo(Principal principal) {
		System.out.println("GroceryStoreController.userInfo()"+ principal.toString());
		final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
		final Authentication authentication = oAuth2Authentication.getUserAuthentication();
//		UserDetails userDetails = (UserDetails)principal;
		System.out.println("authentication.getCredentials().toString()--> "+authentication.getCredentials().toString());
		System.out.println("authentication.getDetails().toString()--> "+authentication.getDetails().toString());
		System.out.println("authentication.getName().toString()--> "+authentication.getName().toString());
		System.out.println("authentication.getAuthorities().toString()--> "+authentication.getAuthorities().toString());
		System.out.println("authentication.getPrincipal().toString()--> "+authentication.getPrincipal().toString());
		   authentication.getCredentials();
		  LoginForm loginForm = new LoginForm(); 
//		  loginForm.setUsername("pournima.shinde@in.ibm.com");
//		  loginForm.setPassword("Horizon@2021");
//		  String userNm = principal.
//		  String pwd = userDetails.getPassword();
		  loginForm.setUsername("pournima.shinde@in.ibm.com");
		  loginForm.setPassword("Horizon@2021");
//		  System.out.println("authentication.getName()--> "+userName);
//		  System.out.println("Principle.getName()--> "+userNm+ " and PWD --> "+pwd);
		  authenticateUser(loginForm);
		 
		// Manually getting the details from the authentication, and returning them as
		// String.
		return authentication.getDetails().toString();
	}


	/*
	 * @Override protected void configure(HttpSecurity http) throws Exception { //
	 * Configuring Spring security access. For /login, /user, and /userinfo, we need
	 * // authentication. // Logout is enabled. // Adding csrf token support to this
	 * configurer. http.authorizeRequests().antMatchers("/login**", "/user",
	 * "/userInfo").authenticated().and().logout()
	 * .logoutSuccessUrl("/").permitAll().and().csrf()
	 * .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()); }
	 * 
	 * @RequestMapping("/user") public Principal user(Principal principal) { //
	 * Principal holds the logged in user information. // Spring automatically
	 * populates this principal object after login. return principal; }
	 * 
	 * @RequestMapping("/userInfo") public String userInfo(Principal principal) {
	 * final OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)
	 * principal; final Authentication authentication =
	 * oAuth2Authentication.getUserAuthentication(); // Manually getting the details
	 * from the authentication, and returning them as // String. return
	 * authentication.getDetails().toString(); }
	 */
}