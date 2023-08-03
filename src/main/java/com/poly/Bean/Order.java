package com.poly.Bean;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Order {
	String idRoom;
	String timeCheckInDate;
	String timeCheckOutDate;
	String nameCustomer;
	String phoneCustomer;
	String emailCustomer;
	String cccd;
	String[] service;
	int numberPeople;
}
