package com.poly.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.poly.Bean.Account;
import com.poly.Bean.MailInformation;
import com.poly.DAO.AccountDAO;
import com.poly.Service.MailServiceImplement;
import com.poly.Service.UserDetailsServiceImpl;
import com.poly.util.password.PasswordUtil;



@Controller
public class AccountController {
	@Autowired
	AccountDAO dao;
	@Autowired
	HttpServletRequest request;
	@Autowired
	UserDetailsServiceImpl service;
	@Autowired
	HttpSession session;
	@Autowired
	MailServiceImplement mailServiceImplement;
	@Autowired
	PasswordUtil passwordUtil;
	

	@PostMapping("/sign-up")
	public String register(@ModelAttribute("account") Account ac, Model model) {
		String repassword= request.getParameter("repassword");
		if (!ac.getPassword().equals(repassword)) {
			model.addAttribute("message", "Xác thực mật khẩu không đúng ");
			return "user/sign-up";
		} else {
			try {
				ac.setAddress(null);
				ac.setCccd(null);
				ac.setRole(new String[] {"USER"});
				ac.setGender(false);
				dao.create(ac);
				System.out.print("tc");
				model.addAttribute("message", "Đăng kí thành công");
				return "redirect:/sign-in";

			} catch (Exception e) {
				model.addAttribute("message", "Đăng kí thất bại");
				System.out.print("tb" );
				return "user/sign-up";
			}
		}

	}
	private String retrievePasswordVerifycode = "";
	private String currentUsernameForgotPassword = "";
	@RequestMapping("/account/retrieve-password")
	public String retrievePassword(Model model,@RequestParam("email")String email){
		try {
			Account ac=dao.findByUsername(email);
			currentUsernameForgotPassword=email;
			MailInformation mail = new MailInformation();
			mail.setTo(ac.getUsername());
			mail.setSubject("Quên mật khẩu");
			String verifyCode=String.valueOf(passwordUtil.generatePassword(6));
			retrievePasswordVerifycode=verifyCode;
			mail.setBody("Mã xác nhận của bạn là: \r\n"+verifyCode);
			mailServiceImplement.send(mail);
			model.addAttribute("message","Mã xác nhận đã được gửi đi, vui lỏng kiểm tra email");
			return "user/forgot-password";
			
		} catch (Exception e) {
			e.printStackTrace();
			model.addAttribute("message","Có lỗi xảy ra");
			
			return "user/forgot-password";
		}
	}
	@RequestMapping("/account/code-retrieve-password")
	public String submitNewPassword(Model model,@RequestParam("verifyCode") String verifyCode) {
		if(!verifyCode.equals(retrievePasswordVerifycode)) {
			model.addAttribute("message","Mã xác nhận không đúng! vui lòng kiểm tra lại.");
			return "user/forgot-password";
		}
		else {
			return "user/forgot-password-finally";
		}
		
	}
	@RequestMapping("/account/submit-retrieve-password")
	public String RetrieveChange(Model model,@RequestParam("newPass") String newPass,
			@RequestParam("rePass")String rePass ) {
		try {
			if(!newPass.equals(rePass)) {
				model.addAttribute("message","Xác nhận mật khẩu chưa chính xác");
				return "user/forgot-password-finally";
			}
			else {
				Account ac= dao.findByUsername(currentUsernameForgotPassword);
				String key=dao.findKeyByUsername(currentUsernameForgotPassword);
				ac.setPassword(newPass);
				dao.update(key, ac);
				model.addAttribute("message","Đổi mật khẩu thành công!");
			}
		} catch (Exception e) {
			model.addAttribute("message","Đổi mật khẩu thất bại!");
			return "user/forgot-password-finally";
			
		}
		return "user/forgot-password-finally";
		
	}

	

	@RequestMapping("/auth/login/form")
	public String form() {
		return "user/sign-in";
	}

	@RequestMapping("/auth/login/success")
	public String success(Model model) {
		
		return "redirect:/";
	}

	@RequestMapping("/auth/login/error")
	public String error(Model model) {
		String username = (String) session.getAttribute("username");
		if (username != null) {
			Account account = dao.findByUsername(username);
			if (account == null) {
				model.addAttribute("message", "Tài khoản không tồn tại");
			} else {
				if (!account.getPassword().equals((String) session.getAttribute("password"))) {
					model.addAttribute("message", "Mật khẩu không chính xác");
				}
			}
		} else {
			model.addAttribute("message", "Vui lòng nhập đầy đủ thông tin");
		}
		return "redirect:/auth/login/form";
	}

	@RequestMapping("/auth/logoff/success")
	public String logout_success(Model model) {
		model.addAttribute("message", "Đăng xuất thành công");
		return "forward:/auth/login/form";
	}

	@RequestMapping("/auth/logoff/error")
	public String logout_error(Model model) {
		model.addAttribute("message", "Đăng xuất thất bại");
		return "forward:/auth/login/form";
	}

	@RequestMapping("/auth/access/denied")
	public String denied(Model model) {
		return "redirect:/";
	}

	@RequestMapping("/oauth2/login/success")
	public String googleSucces(OAuth2AuthenticationToken oauth2) {
		service.loginFromOAuth2(oauth2);
		return "redirect:/";
	}
}