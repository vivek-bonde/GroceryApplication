package com.grocery;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;


import com.grocery.model.GroceriesInventory;




@FeignClient(name="GROCERY-STORE")
public interface GroceryServiceProxy {

	@GetMapping("/grocery-order")
	public GroceriesInventory getGroceryOrder();

}
