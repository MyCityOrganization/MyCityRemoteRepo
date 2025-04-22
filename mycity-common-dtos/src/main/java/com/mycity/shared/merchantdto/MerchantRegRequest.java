package com.mycity.shared.merchantdto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MerchantRegRequest {

	    private String name;
	    private String email;
	    private String password;
	    private String phoneNumber;
	    private String businessName;
	    private String businessAddress;
	    private String gstNumber;
		private boolean isOtpVerified;
	}
