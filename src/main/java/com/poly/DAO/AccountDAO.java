package com.poly.DAO;

import org.springframework.http.HttpEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;


import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.poly.Bean.Account;
import com.poly.Bean.AccountMap;

@Repository
public class AccountDAO {
	RestTemplate rest = new RestTemplate();
	String url = "https://dothanhven-java6-default-rtdb.firebaseio.com/accounts.json";

	private String getUrl(String key) {
		return url.replace(".json", "/" + key + ".json");
	}

	public AccountMap findAll() {
		return rest.getForObject(url, AccountMap.class);
	}

	public Account findByKey(String key) {
		return rest.getForObject(getUrl(key), Account.class);
	}

	public String create(Account data) {
		// Mã hóa mật khẩu trước khi lưu vào Firebase
//		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//		String encodedPassword = passwordEncoder.encode(data.getPassword());
//		data.setPassword(encodedPassword);

		HttpEntity<Account> entity = new HttpEntity<>(data);
		JsonNode resp = rest.postForObject(url, entity, JsonNode.class);
		return resp.get("name").asText();
	}

	public Account update(String key, Account data) {
		// Mã hóa mật khẩu trước khi cập nhật vào Firebase
//		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//		String encodedPassword = passwordEncoder.encode(data.getPassword());
//		data.setPassword(encodedPassword);

		HttpEntity<Account> entity = new HttpEntity<>(data);
		rest.put(getUrl(key), entity);
		return data;
	}

	public void delete(String key) {
		rest.delete(getUrl(key));
	}

	public Account findByUsername(String username) {
		AccountMap accountMap = findAll();
		for (Account account : accountMap.values()) {
			if (username.equals(account.getUsername())) {
				return account;
			}
		}
		return null;
	}
	public String findKeyByUsername(String target) {
		String jsonStr = rest.getForObject(url, String.class);
		JsonObject jsonObject = JsonParser.parseString(jsonStr).getAsJsonObject();
		for(String key:jsonObject.keySet()) {
			JsonObject object = jsonObject.getAsJsonObject(key);
			if(object.has("username") && target.equals(object.get("username").getAsString())) {
				return key;
			}
		}
		return null;
	}

}
