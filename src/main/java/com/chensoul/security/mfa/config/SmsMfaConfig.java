package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.MfaProviderType;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class SmsMfaConfig extends OtpBasedMfaConfig {

	@NotBlank
	@Pattern(regexp = "^\\+[1-9]\\d{1,14}$", message = "is not of E.164 format")
	private String phoneNumber;

	@Override
	public MfaProviderType getProviderType() {
		return MfaProviderType.SMS;
	}

}
