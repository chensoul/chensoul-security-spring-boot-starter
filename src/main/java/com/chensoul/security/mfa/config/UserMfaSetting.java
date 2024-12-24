package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.MfaProviderType;
import java.util.LinkedHashMap;
import lombok.Data;

@Data
public class UserMfaSetting {
	private LinkedHashMap<MfaProviderType, MfaConfig> configs;
}
