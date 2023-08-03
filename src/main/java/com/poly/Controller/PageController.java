package com.poly.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.poly.Bean.Account;

@Controller
public class PageController {
	// CUSTOMER
	@GetMapping("/")
	public String home() {
		return "user/index";
	}

	@GetMapping("/sign-in")
	public String login() {
		return "user/sign-in";
	}

	@GetMapping("/sign-up")
	public String login(Model model) {
		model.addAttribute("account",new Account());
		return "user/sign-up";
	}

	@GetMapping("/forgot-password")
	public String forgotPassword() {
		return "user/forgot-password";
	}

	@GetMapping("/forgot-password-finally")
	public String forgotPasswordFinally() {
		return "user/forgot-password-finally";
	}

	@GetMapping("/infomation-room")
	public String infomationRoom() {
		return "user/infomation-room";
	}

	@GetMapping("/change-password")
	public String changePassword() {
		return "user/change-password";
	}

	@GetMapping("/info-user")
	public String infoUser() {
		return "user/info-user";
	}

	@GetMapping("/order-history")
	public String orderHistory() {
		return "user/order-history";
	}

	// ADMIN
	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/admin/index")
	public String adminHome() {
		return "admin/index";
	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/admin/customer")
	public String managerCustomr() {
		return "admin/customer";
	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/admin/type-room")
	public String typeRoom() {
		return "admin/type-room";
	}

	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/admin/service-room")
	public String serviceRoom() {
		return "admin/service-room";
	}
	
	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/admin/room")
	public String managerRoom() {
		return "admin/room";
	}
}
