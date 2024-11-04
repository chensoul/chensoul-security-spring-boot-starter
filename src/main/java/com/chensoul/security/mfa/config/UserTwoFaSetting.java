package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.TwoFaProviderType;
import java.util.LinkedHashMap;
import lombok.Data;

@Data
public class UserTwoFaSetting {
	private LinkedHashMap<TwoFaProviderType, TwoFaConfig> configs;
}
