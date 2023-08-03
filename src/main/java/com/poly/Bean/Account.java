package com.poly.Bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Account {
	String username;
	String password;
	String cccd;
	String fullname;
	String[] role;
	String address;
	boolean gender;
}
