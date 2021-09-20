package com.grocery.controller;

import java.security.Principal;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.grocery.GroceryServiceProxy;
import com.grocery.model.GroceriesInventory;
import com.grocery.model.LoginForm;
import com.grocery.repo.UserRepository;
import com.grocery.security.JwtProvider;
import com.grocery.security.JwtResponse;




@Controller
public class GroceryStoreController {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	/*
	 * @Autowired AuthenticationManager authenticationManager;
	 * 
	 * @Autowired UserRepository userRepository;
	 * 
	 * // @Autowired // RoleRepository roleRepository;
	 * 
	 * @Autowired PasswordEncoder encoder;
	 * 
	 * @Autowired JwtProvider jwtProvider;
	 * 
	 * @Autowired private GroceryServiceProxy proxy;
	 */
	
//	@PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {
//
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        loginRequest.getUsername(),
//                        loginRequest.getPassword()
//                )
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        String jwt = jwtProvider.generateJwtToken(authentication);
//        return ResponseEntity.ok(new JwtResponse(jwt));
//    }
	

	/*
	 * @GetMapping("/grocery-order") public GroceriesInventory getGroceryOrder() {
	 * System.out.println("GroceryStoreController.getGroceryOrder()");
	 * GroceriesInventory groceriesInventory = proxy.getGroceryOrder();
	 * logger.info("{}",groceriesInventory); return new GroceriesInventory();
	 * 
	 * }
	 */
}
