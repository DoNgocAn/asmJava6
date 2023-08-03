package com.poly.Controller;

import java.net.http.HttpRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import com.poly.Bean.Order;
import com.poly.Bean.OrderMap;
import com.poly.DAO.OrderDAO;

@Controller
public class OrderController {
	@Autowired
	OrderDAO dao;

	@RequestMapping("/admin/orders")
	public String HomeOrder(Model model) {
		OrderMap orders = dao.findAll();
		model.addAttribute("rooms", orders);
		return "admin/order";
	}

	@RequestMapping("/admin/orders/detail-room/{id}")
	public String showModal(@PathVariable("id") String id, Model model) {
		Order order = dao.findByKey(id);
		model.addAttribute("room", order);
		return "admin/modal-detail-room";
	}

	@Autowired
	HttpServletRequest request;

	@RequestMapping("/update/detail-room-serivce/{id}")
	public String updateService(@PathVariable("id") int id, Model model) {
		model.addAttribute("id", id);
		HttpSession session = request.getSession();
		session.setAttribute("message", "Sửa thành công phòng " + id);
		return "redirect:/admin/orders";
	}
}
