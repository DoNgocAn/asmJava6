package com.poly.DAO;

import org.springframework.http.HttpEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.poly.Bean.Order;
import com.poly.Bean.OrderMap;

@Repository
public class OrderDAO {
	RestTemplate rest = new RestTemplate();
	String url = "https://dothanhven-java6-default-rtdb.firebaseio.com/orders.json";

	private String getUrl(String key) {
		return url.replace(".json", "/" + key + ".json");
	}

	public OrderMap findAll() {
		return rest.getForObject(url, OrderMap.class);
	}

	public Order findByKey(String key) {
		return rest.getForObject(getUrl(key), Order.class);
	}

	public String create(Order data) {
		HttpEntity<Order> entity = new HttpEntity<>(data);
		JsonNode resp = rest.postForObject(url, entity, JsonNode.class);
		return resp.get("name").asText();
	}

	public Order update(String key, Order data) {
		HttpEntity<Order> entity = new HttpEntity<>(data);
		rest.put(getUrl(key), entity);
		return data;
	}

	public void delete(String key) {
		rest.delete(getUrl(key));
	}

	public Order findByIdRoom(String idRoom) {
		OrderMap orderMap = findAll();
		for (Order order : orderMap.values()) {
			if (idRoom.equals(order.getIdRoom())) {
				return order;
			}
		}
		return null;
	}

}
